package archiveio

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

func FuzzInspectNeverPanics(f *testing.F) {
	f.Add(fuzzZIPBytes("file.txt", []byte("zip seed"), 0o644))
	f.Add(fuzzTARBytes("file.txt", []byte("tar seed"), 0o644, false))
	f.Add(fuzzTARBytes("file.txt", []byte("gzip seed"), 0o644, true))
	f.Add([]byte("not an archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<10 {
			t.Skip()
		}
		limits := archiveLimits{entries: 32, entrySize: 16 << 10, totalSize: 64 << 10}
		first, err := fuzzInspectBytes(data, limits)
		if err != nil {
			return
		}
		second, err := fuzzInspectBytes(data, limits)
		if err != nil {
			t.Fatalf("second inspection failed: %v", err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("inspection is not deterministic: %#v != %#v", first, second)
		}
		if first.ContentSHA256 != contentRoot(first.Entries) || !isLowerDigest(first.ByteSHA256) || !isLowerDigest(first.ContentSHA256) {
			t.Fatalf("invalid snapshot identities: %#v", first)
		}
		if len(first.Entries) > limits.entries || len(first.Order) != len(first.Entries) {
			t.Fatalf("snapshot limits or ordering violated: %#v", first)
		}
		seen := make(map[string]struct{}, len(first.Entries))
		folded := make(map[string]string, len(first.Entries))
		var total int64
		var pathTotal int64
		for index, entry := range first.Entries {
			if _, err := safeArchivePath(entry.Path); err != nil {
				t.Fatalf("unsafe successful path: %v", err)
			}
			if err := registerPath(entry.Path, seen, folded); err != nil {
				t.Fatal(err)
			}
			if err := addPathSize(entry.Path, &pathTotal); err != nil {
				t.Fatal(err)
			}
			if entry.Kind != "directory" {
				if err := checkSizeWithLimits(entry.Size, &total, limits); err != nil {
					t.Fatal(err)
				}
			}
			if first.Order[index] != entry.Path || !isLowerDigest(entry.SHA256) {
				t.Fatalf("entry receipt is inconsistent: %#v", entry)
			}
		}
	})
}

func fuzzInspectBytes(data []byte, limits archiveLimits) (Snapshot, error) {
	input := bytes.NewReader(data)
	format, err := detectFormat(input)
	if err != nil {
		return Snapshot{}, err
	}
	var entries []Entry
	var order []string
	switch format {
	case "zip":
		reader, zipErr := zip.NewReader(input, int64(len(data)))
		if zipErr != nil {
			return Snapshot{}, zipErr
		}
		entries, order, err = readZIP(reader, limits)
	case "tar", "tar.gz":
		entries, order, err = readTAR(input, format == "tar.gz", limits)
	}
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Archive:       "fuzz.archive",
		Format:        format,
		ByteSHA256:    hashBytes(data),
		ContentSHA256: contentRoot(entries),
		Entries:       entries,
		Order:         order,
	}, nil
}

func FuzzDecodeManifestStrict(f *testing.F) {
	manifest := fuzzManifest()
	var encoded bytes.Buffer
	if err := EncodeManifest(&encoded, manifest); err != nil {
		f.Fatal(err)
	}
	f.Add(encoded.Bytes())
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"format":"samepack-manifest","format":"duplicate"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8<<10 {
			t.Skip()
		}
		decoded, err := DecodeManifest(bytes.NewReader(data))
		if err != nil {
			return
		}
		if err := ValidateManifest(decoded); err != nil {
			t.Fatalf("decoder returned invalid manifest: %v", err)
		}
		var first, second bytes.Buffer
		if err := EncodeManifest(&first, decoded); err != nil {
			t.Fatal(err)
		}
		if err := EncodeManifest(&second, decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Fatal("manifest encoding is not deterministic")
		}
		roundTrip, err := DecodeManifest(bytes.NewReader(first.Bytes()))
		if err != nil || !reflect.DeepEqual(decoded, roundTrip) {
			t.Fatalf("manifest round trip failed: %#v, %v", roundTrip, err)
		}
	})
}

func FuzzRecordVerifyCrossFormat(f *testing.F) {
	f.Add([]byte("same payload"), uint8(0))
	f.Add([]byte("#!/bin/sh\necho hi\n"), uint8(1))
	f.Fuzz(func(t *testing.T, body []byte, executableFlag uint8) {
		if len(body) > 64<<10 {
			t.Skip()
		}
		executable := executableFlag&1 == 1
		zipMode := int64(0o666)
		tarMode := int64(0o664)
		if executable {
			zipMode = 0o777
			tarMode = 0o775
		}
		zipPath := filepath.Join(t.TempDir(), "source.zip")
		tarPath := filepath.Join(t.TempDir(), "source.tar.gz")
		if err := os.WriteFile(zipPath, fuzzZIPBytes("project/file.bin", body, zipMode), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tarPath, fuzzTARBytes("project/file.bin", body, tarMode, true), 0o644); err != nil {
			t.Fatal(err)
		}
		zipSnapshot, err := Inspect(zipPath)
		if err != nil {
			t.Fatal(err)
		}
		tarSnapshot, err := Inspect(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, policy := range []string{WrapperNone, WrapperStripSingle} {
			manifest, err := CreateManifest(zipSnapshot, policy)
			if err != nil {
				t.Fatal(err)
			}
			result, err := VerifyManifest(manifest, tarSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Match {
				t.Fatalf("cross-format portable payload differs under %s: %#v", policy, result)
			}
		}
	})
}

func FuzzVerifyPinpointsMutation(f *testing.F) {
	f.Add(uint8(0), []byte("delta"))
	f.Add(uint8(1), []byte(""))
	f.Add(uint8(2), []byte("changed"))
	f.Add(uint8(3), []byte(""))
	f.Fuzz(func(t *testing.T, operation uint8, delta []byte) {
		if len(delta) > 64<<10 {
			t.Skip()
		}
		baseline := fuzzSnapshot([]Entry{
			fuzzEntry("a.txt", []byte("alpha"), false),
			fuzzEntry("b.txt", []byte("beta"), false),
			fuzzEntry("c.txt", []byte("gamma"), false),
		})
		manifest, err := CreateManifest(baseline, WrapperNone)
		if err != nil {
			t.Fatal(err)
		}
		candidate := append([]Entry(nil), baseline.Entries...)
		target := "b.txt"
		switch operation % 4 {
		case 0:
			target = "d.txt"
			candidate = append(candidate, fuzzEntry(target, delta, false))
		case 1:
			candidate = slices.Delete(candidate, 1, 2)
		case 2:
			if bytes.Equal(delta, []byte("beta")) {
				delta = append(append([]byte(nil), delta...), 0)
			}
			candidate[1] = fuzzEntry(target, delta, false)
		case 3:
			candidate[1].Mode = 0o755
		}
		observed := fuzzSnapshot(candidate)
		result, err := VerifyManifest(manifest, observed)
		if err != nil {
			t.Fatal(err)
		}
		if result.Match {
			t.Fatalf("mutation %d unexpectedly matched", operation%4)
		}
		if !verificationNamesPath(result, target) {
			t.Fatalf("mutation did not identify %q: %#v", target, result)
		}
	})
}

func fuzzZIPBytes(name string, body []byte, mode int64) []byte {
	var output bytes.Buffer
	w := zip.NewWriter(&output)
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(os.FileMode(mode))
	header.SetModTime(time.Date(2030, 1, 2, 3, 4, 6, 0, time.UTC))
	part, err := w.CreateHeader(header)
	if err != nil {
		panic(err)
	}
	if _, err := part.Write(body); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return output.Bytes()
}

func fuzzTARBytes(name string, body []byte, mode int64, compressed bool) []byte {
	var output bytes.Buffer
	var destination bytes.Buffer
	writer := &output
	var gz *gzip.Writer
	if compressed {
		gz = gzip.NewWriter(&destination)
		writer = &bytes.Buffer{}
	}
	var target interface{ Write([]byte) (int, error) } = writer
	if compressed {
		target = gz
	}
	tarWriter := tar.NewWriter(target)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), ModTime: time.Unix(10, 0)}); err != nil {
		panic(err)
	}
	if _, err := tarWriter.Write(body); err != nil {
		panic(err)
	}
	if err := tarWriter.Close(); err != nil {
		panic(err)
	}
	if compressed {
		if err := gz.Close(); err != nil {
			panic(err)
		}
		return destination.Bytes()
	}
	return output.Bytes()
}

func fuzzManifest() Manifest {
	entries := []ManifestEntry{{
		Path:   "file.txt",
		Kind:   "file",
		Size:   0,
		SHA256: emptyDigest(),
	}}
	root, err := portableRoot(entries, WrapperNone)
	if err != nil {
		panic(err)
	}
	return Manifest{
		Format:        ManifestFormat,
		Version:       ManifestVersion,
		Algorithm:     ManifestAlgorithm,
		RootSHA256:    root,
		PayloadSHA256: contentRoot(entriesFromManifest(entries)),
		Normalization: ManifestNormalization{Wrapper: WrapperNone},
		Source:        ManifestSource{Format: "zip", ArtifactSHA256: emptyDigest()},
		Entries:       entries,
	}
}

func fuzzEntry(name string, body []byte, executable bool) Entry {
	mode := uint32(0o644)
	if executable {
		mode = 0o755
	}
	return Entry{Path: name, Kind: "file", Size: int64(len(body)), SHA256: hashBytes(body), Mode: mode}
}

func fuzzSnapshot(entries []Entry) Snapshot {
	ordered := append([]Entry(nil), entries...)
	slices.SortFunc(ordered, func(left, right Entry) int {
		if left.Path < right.Path {
			return -1
		}
		if left.Path > right.Path {
			return 1
		}
		return 0
	})
	order := make([]string, len(ordered))
	for index := range ordered {
		order[index] = ordered[index].Path
	}
	return Snapshot{
		Archive:       "fuzz.zip",
		Format:        "zip",
		ByteSHA256:    emptyDigest(),
		ContentSHA256: contentRoot(ordered),
		Entries:       ordered,
		Order:         order,
	}
}

func verificationNamesPath(result Verification, target string) bool {
	if slices.Contains(result.Added, target) || slices.Contains(result.Removed, target) {
		return true
	}
	for _, change := range result.Modified {
		if change.Path == target {
			return true
		}
	}
	for _, change := range result.ExecutableChanged {
		if change.Path == target {
			return true
		}
	}
	return false
}

func isLowerDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == string(bytes.ToLower([]byte(value)))
}
