package archiveio

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestManifestIsDeterministicAndPathIndependent(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.zip")
	writeZIPFixture(t, first, []fixtureEntry{
		{name: "b.txt", body: "beta"},
		{name: "a.txt", body: "alpha"},
	})
	copyPath := filepath.Join(t.TempDir(), "renamed.zip")
	if err := os.WriteFile(copyPath, mustRead(t, first), 0o644); err != nil {
		t.Fatal(err)
	}

	leftSnapshot, err := Inspect(first)
	if err != nil {
		t.Fatal(err)
	}
	rightSnapshot, err := Inspect(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	left, err := CreateManifest(leftSnapshot, WrapperNone)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CreateManifest(rightSnapshot, WrapperNone)
	if err != nil {
		t.Fatal(err)
	}
	var leftJSON, rightJSON bytes.Buffer
	if err := EncodeManifest(&leftJSON, left); err != nil {
		t.Fatal(err)
	}
	if err := EncodeManifest(&rightJSON, right); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftJSON.Bytes(), rightJSON.Bytes()) {
		t.Fatalf("manifest depends on local filename:\n%s\n%s", leftJSON.Bytes(), rightJSON.Bytes())
	}
	if strings.Contains(leftJSON.String(), filepath.Dir(first)) || strings.Contains(leftJSON.String(), "created_at") {
		t.Fatalf("manifest leaked local or time-dependent data: %s", leftJSON.String())
	}
	if got := []string{left.Entries[0].Path, left.Entries[1].Path}; !slices.Equal(got, []string{"a.txt", "b.txt"}) {
		t.Fatalf("entries are not sorted: %#v", got)
	}
}

func TestManifestV1GoldenPortableRoot(t *testing.T) {
	manifest := fuzzManifest()
	const expected = "d3d9e869bf6d85b62cd2c1636aa21f30d3ba63cc763f38b9842d1f2d2cd57e87"
	if manifest.RootSHA256 != expected {
		t.Fatalf("portable-v1 root changed: got %s", manifest.RootSHA256)
	}
}

func TestManifestEncoderEnforcesReaderSizeLimit(t *testing.T) {
	manifest := fuzzManifest()
	encoded, err := encodeManifestBytes(manifest, maxManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encodeManifestBytes(manifest, int64(len(encoded)-1)); err == nil {
		t.Fatal("encoder produced a manifest larger than its decoder limit")
	}
}

func TestManifestWrapperPolicyIsPersistedAndIndependent(t *testing.T) {
	baselinePath := filepath.Join(t.TempDir(), "baseline.zip")
	renamedPath := filepath.Join(t.TempDir(), "renamed.zip")
	unwrappedPath := filepath.Join(t.TempDir(), "unwrapped.zip")
	writeZIPFixture(t, baselinePath, []fixtureEntry{{name: "project-1/README.md", body: "same"}})
	writeZIPFixture(t, renamedPath, []fixtureEntry{{name: "project-2/README.md", body: "same"}})
	writeZIPFixture(t, unwrappedPath, []fixtureEntry{{name: "README.md", body: "same"}})

	baseline, _ := Inspect(baselinePath)
	manifest, err := CreateManifest(baseline, WrapperStripSingle)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Source.StrippedRoot != "project-1" || manifest.Normalization.Wrapper != WrapperStripSingle {
		t.Fatalf("wrapper receipt missing: %#v", manifest)
	}
	for _, candidate := range []string{renamedPath, unwrappedPath} {
		snapshot, _ := Inspect(candidate)
		result, err := VerifyManifest(manifest, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Match {
			t.Fatalf("persisted wrapper policy did not match %s: %#v", candidate, result)
		}
	}

	exact, err := CreateManifest(baseline, WrapperNone)
	if err != nil {
		t.Fatal(err)
	}
	renamed, _ := Inspect(renamedPath)
	result, err := VerifyManifest(exact, renamed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Match || result.Classification != "payload_changed" {
		t.Fatalf("exact policy hid a root rename: %#v", result)
	}
}

func TestManifestNormalizesPermissionNoiseButTracksExecutability(t *testing.T) {
	baselinePath := filepath.Join(t.TempDir(), "baseline.zip")
	permissionNoisePath := filepath.Join(t.TempDir(), "permission-noise.zip")
	executablePath := filepath.Join(t.TempDir(), "executable.zip")
	writeZIPFixture(t, baselinePath, []fixtureEntry{{name: "run.sh", body: "echo hi", mode: 0o644}})
	writeZIPFixture(t, permissionNoisePath, []fixtureEntry{{name: "run.sh", body: "echo hi", mode: 0o666}})
	writeZIPFixture(t, executablePath, []fixtureEntry{{name: "run.sh", body: "echo hi", mode: 0o755}})

	baseline, _ := Inspect(baselinePath)
	manifest, err := CreateManifest(baseline, WrapperNone)
	if err != nil {
		t.Fatal(err)
	}
	permissionNoise, _ := Inspect(permissionNoisePath)
	matched, err := VerifyManifest(manifest, permissionNoise)
	if err != nil || !matched.Match {
		t.Fatalf("read/write permission noise should be normalized: %#v, %v", matched, err)
	}
	executable, _ := Inspect(executablePath)
	changed, err := VerifyManifest(manifest, executable)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Match || !changed.PayloadIdentical || changed.Classification != "behavior_changed" || len(changed.ExecutableChanged) != 1 {
		t.Fatalf("executable change was not isolated: %#v", changed)
	}
}

func TestVerifyManifestPinpointsSortedPayloadChanges(t *testing.T) {
	baselinePath := filepath.Join(t.TempDir(), "baseline.zip")
	changedPath := filepath.Join(t.TempDir(), "changed.zip")
	writeZIPFixture(t, baselinePath, []fixtureEntry{
		{name: "a.txt", body: "same"},
		{name: "b.txt", body: "before"},
		{name: "c.txt", body: "removed"},
	})
	writeZIPFixture(t, changedPath, []fixtureEntry{
		{name: "d.txt", body: "added"},
		{name: "b.txt", body: "after"},
		{name: "a.txt", body: "same"},
	})
	baseline, _ := Inspect(baselinePath)
	manifest, _ := CreateManifest(baseline, WrapperNone)
	changed, _ := Inspect(changedPath)
	result, err := VerifyManifest(manifest, changed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Match || !slices.Equal(result.Added, []string{"d.txt"}) || !slices.Equal(result.Removed, []string{"c.txt"}) {
		t.Fatalf("wrong added/removed paths: %#v", result)
	}
	if len(result.Modified) != 1 || result.Modified[0].Path != "b.txt" {
		t.Fatalf("wrong modified paths: %#v", result.Modified)
	}
}

func TestVerifyManifestDetectsKindChangeWithSameBytes(t *testing.T) {
	baselinePath := filepath.Join(t.TempDir(), "baseline.zip")
	symlinkPath := filepath.Join(t.TempDir(), "symlink.zip")
	writeZIPFixture(t, baselinePath, []fixtureEntry{{name: "current", body: "target", mode: 0o644}})
	writeZIPFixture(t, symlinkPath, []fixtureEntry{{name: "current", body: "target", mode: os.ModeSymlink | 0o777}})
	baseline, _ := Inspect(baselinePath)
	manifest, _ := CreateManifest(baseline, WrapperNone)
	symlink, err := Inspect(symlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyManifest(manifest, symlink)
	if err != nil {
		t.Fatal(err)
	}
	if result.Match || len(result.Modified) != 1 || result.Modified[0].ExpectedKind != "file" || result.Modified[0].ObservedKind != "symlink" {
		t.Fatalf("kind change was hidden: %#v", result)
	}
}

func TestManifestIgnoresExplicitDirectoryRecords(t *testing.T) {
	withDirectory := filepath.Join(t.TempDir(), "with.zip")
	withoutDirectory := filepath.Join(t.TempDir(), "without.zip")
	writeZIPFixture(t, withDirectory, []fixtureEntry{
		{name: "empty/", mode: os.ModeDir | 0o755},
		{name: "file.txt", body: "same"},
	})
	writeZIPFixture(t, withoutDirectory, []fixtureEntry{{name: "file.txt", body: "same"}})
	left, _ := Inspect(withDirectory)
	manifest, _ := CreateManifest(left, WrapperNone)
	right, _ := Inspect(withoutDirectory)
	result, err := VerifyManifest(manifest, right)
	if err != nil || !result.Match {
		t.Fatalf("directory encoding leaked into portable payload: %#v, %v", result, err)
	}
}

func TestDecodeManifestRejectsAmbiguousAndNonCanonicalDocuments(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "baseline.zip")
	writeZIPFixture(t, archive, []fixtureEntry{
		{name: "a.txt", body: "alpha"},
		{name: "b.txt", body: "beta"},
	})
	snapshot, _ := Inspect(archive)
	valid, _ := CreateManifest(snapshot, WrapperNone)
	validJSON := rawManifestJSON(t, valid)

	rawCases := map[string][]byte{
		"unknown field":         bytes.Replace(validJSON, []byte("{"), []byte(`{"unknown":true,`), 1),
		"duplicate key":         bytes.Replace(validJSON, []byte(`"format":"samepack-manifest"`), []byte(`"format":"wrong","format":"samepack-manifest"`), 1),
		"case variant key":      bytes.Replace(validJSON, []byte(`"format":"samepack-manifest"`), []byte(`"FORMAT":"samepack-manifest"`), 1),
		"case alias overwrite":  bytes.Replace(validJSON, []byte(`"format":"samepack-manifest"`), []byte(`"format":"wrong","FORMAT":"samepack-manifest"`), 1),
		"nested case key":       bytes.Replace(validJSON, []byte(`"wrapper":"none"`), []byte(`"Wrapper":"none"`), 1),
		"missing explicit bool": bytes.Replace(validJSON, []byte(`,"executable":false`), nil, 1),
		"null executable":       bytes.Replace(validJSON, []byte(`"executable":false`), []byte(`"executable":null`), 1),
		"null zero size":        bytes.Replace(validJSON, []byte(`"size":5`), []byte(`"size":null`), 1),
		"null stripped root":    bytes.Replace(validJSON, []byte(`"artifact_sha256":`), []byte(`"stripped_root":null,"artifact_sha256":`), 1),
		"trailing value":        append(append([]byte(nil), validJSON...), []byte(` {}`)...),
		"invalid utf8":          append([]byte(`{"format":"`), 0xff, '}'),
		"surrogate object key":  bytes.Replace(validJSON, []byte(`"format"`), []byte(`"\ud800"`), 1),
		"surrogate path":        bytes.Replace(validJSON, []byte(`"path":"a.txt"`), []byte(`"path":"\ud800"`), 1),
		"surrogate value":       bytes.Replace(validJSON, []byte(`"format":"zip"`), []byte(`"format":"\udfff"`), 1),
		"surrogate wrong pair":  bytes.Replace(validJSON, []byte(`"path":"a.txt"`), []byte(`"path":"\ud800\u0061"`), 1),
	}
	for name, data := range rawCases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeManifest(bytes.NewReader(data)); err == nil {
				t.Fatalf("accepted invalid document: %q", data)
			}
		})
	}

	mutations := map[string]func(*Manifest){
		"format":           func(m *Manifest) { m.Format = "other" },
		"version":          func(m *Manifest) { m.Version++ },
		"algorithm":        func(m *Manifest) { m.Algorithm = "other" },
		"wrapper":          func(m *Manifest) { m.Normalization.Wrapper = "other" },
		"uppercase digest": func(m *Manifest) { m.Entries[0].SHA256 = strings.ToUpper(m.Entries[0].SHA256) },
		"negative size":    func(m *Manifest) { m.Entries[0].Size = -1 },
		"unsafe path":      func(m *Manifest) { m.Entries[0].Path = "../a.txt" },
		"unsorted":         func(m *Manifest) { m.Entries[0], m.Entries[1] = m.Entries[1], m.Entries[0] },
		"duplicate":        func(m *Manifest) { m.Entries[1] = m.Entries[0] },
		"case collision":   func(m *Manifest) { m.Entries[1].Path = "A.txt" },
		"path graph":       func(m *Manifest) { m.Entries[0].Path, m.Entries[1].Path = "a", "a/b" },
		"case path graph":  func(m *Manifest) { m.Entries[0].Path, m.Entries[1].Path = "A", "a/b" },
		"directory":        func(m *Manifest) { m.Entries[0].Kind = "directory" },
		"executable link":  func(m *Manifest) { m.Entries[0].Kind, m.Entries[0].Executable = "symlink", true },
		"null entries":     func(m *Manifest) { m.Entries = nil },
		"root mismatch":    func(m *Manifest) { m.RootSHA256 = strings.Repeat("0", 64) },
		"payload mismatch": func(m *Manifest) { m.PayloadSHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneManifest(t, valid)
			mutate(&candidate)
			if _, err := DecodeManifest(bytes.NewReader(rawManifestJSON(t, candidate))); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
}

func TestDecodeManifestAcceptsPairedSurrogateEscape(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "unicode.zip")
	writeZIPFixture(t, archive, []fixtureEntry{{name: "🚀.txt", body: "launch"}})
	snapshot, err := Inspect(archive)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := CreateManifest(snapshot, WrapperNone)
	if err != nil {
		t.Fatal(err)
	}
	encoded := rawManifestJSON(t, manifest)
	escaped := bytes.ReplaceAll(encoded, []byte("🚀"), []byte(`\ud83d\ude80`))
	decoded, err := DecodeManifest(bytes.NewReader(escaped))
	if err != nil {
		t.Fatalf("valid surrogate pair was rejected: %v", err)
	}
	if decoded.Entries[0].Path != "🚀.txt" {
		t.Fatalf("surrogate pair decoded as %q", decoded.Entries[0].Path)
	}
}

func TestWriteManifestCannotOverwrite(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "baseline.zip")
	writeZIPFixture(t, archive, []fixtureEntry{{name: "a.txt", body: "alpha"}})
	snapshot, _ := Inspect(archive)
	manifest, _ := CreateManifest(snapshot, WrapperNone)
	output := filepath.Join(t.TempDir(), "baseline.samepack.json")
	if err := WriteManifest(output, manifest); err != nil {
		t.Fatal(err)
	}
	original := mustRead(t, output)
	if err := WriteManifest(output, manifest); err == nil {
		t.Fatal("manifest output was overwritten")
	}
	if !bytes.Equal(original, mustRead(t, output)) {
		t.Fatal("existing manifest changed after refused overwrite")
	}
}

func TestSafeArchivePathRejectsInvalidUTF8(t *testing.T) {
	if _, err := safeArchivePath(string([]byte{'a', 0xff})); err == nil {
		t.Fatal("accepted invalid UTF-8 archive path")
	}
}

func rawManifestJSON(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneManifest(t *testing.T, manifest Manifest) Manifest {
	t.Helper()
	data := rawManifestJSON(t, manifest)
	var clone Manifest
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
