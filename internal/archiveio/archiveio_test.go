package archiveio

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPackIsDeterministicAcrossSourceTimestamps(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "bin", "samepack"), "binary payload")
	mustWrite(t, filepath.Join(root, "README.md"), "hello\n")
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(t.TempDir(), "first.tar.gz")
	second := filepath.Join(t.TempDir(), "second.tar.gz")

	left, err := Pack(root, first, "tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	changed := time.Date(2038, 1, 19, 3, 14, 7, 0, time.UTC)
	if err := filepath.Walk(root, func(path string, _ os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Chtimes(path, changed, changed)
	}); err != nil {
		t.Fatal(err)
	}
	right, err := Pack(root, second, "tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if left.ByteSHA256 != right.ByteSHA256 {
		t.Fatalf("canonical archives differ: %s != %s", left.ByteSHA256, right.ByteSHA256)
	}
	if !bytes.Equal(mustRead(t, first), mustRead(t, second)) {
		t.Fatal("canonical archives are not byte-identical")
	}
}

func TestCanonicalFileModePreservesExecutableBehavior(t *testing.T) {
	if got := canonicalFileMode(modeFileInfo{mode: 0o755}, true); got != 0o755 {
		t.Fatalf("executable bit was lost: mode %04o", got)
	}
	if got := canonicalFileMode(modeFileInfo{mode: 0o755}, false); got != 0o644 {
		t.Fatalf("default mode depends on host executable metadata: mode %04o", got)
	}
	if got := canonicalFileMode(modeFileInfo{mode: 0o666}, true); got != 0o644 {
		t.Fatalf("read/write permission noise was not normalized: mode %04o", got)
	}
}

func TestPackExecutableModePolicyEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filesystems do not expose POSIX executable status consistently")
	}
	root := t.TempDir()
	script := filepath.Join(root, "run.sh")
	mustWrite(t, script, "#!/bin/sh\necho hi\n")
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}

	normalized, err := Pack(root, filepath.Join(t.TempDir(), "normalized.tar"), "tar")
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := PackWithOptions(root, filepath.Join(t.TempDir(), "preserved.tar"), PackOptions{
		Format:             "tar",
		PreserveExecutable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Entries) != 1 || normalized.Entries[0].Mode != 0o644 {
		t.Fatalf("default pack did not normalize to 0644: %#v", normalized.Entries)
	}
	if len(preserved.Entries) != 1 || preserved.Entries[0].Mode != 0o755 {
		t.Fatalf("opt-in pack did not preserve executable status: %#v", preserved.Entries)
	}
}

func TestCompareClassifiesMetadataOnly(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.zip")
	second := filepath.Join(t.TempDir(), "second.zip")
	writeZIPFixture(t, first, []fixtureEntry{
		{name: "a.txt", body: "alpha", modTime: time.Unix(1, 0)},
		{name: "b.txt", body: "beta", modTime: time.Unix(2, 0)},
	})
	writeZIPFixture(t, second, []fixtureEntry{
		{name: "b.txt", body: "beta", modTime: time.Unix(200, 0)},
		{name: "a.txt", body: "alpha", modTime: time.Unix(100, 0)},
	})
	left, err := Inspect(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Inspect(second)
	if err != nil {
		t.Fatal(err)
	}
	comparison := Compare(left, right)
	if comparison.Classification != "metadata_only" || !comparison.ContentIdentical {
		t.Fatalf("unexpected classification: %#v", comparison)
	}
	if !comparison.OrderChanged || !slices.Contains(comparison.Reasons, "entry order changed") {
		t.Fatalf("entry order difference not explained: %#v", comparison.Reasons)
	}
	if !slices.Contains(comparison.Reasons, "entry timestamps changed") {
		t.Fatalf("timestamp difference not explained: %#v", comparison.Reasons)
	}
}

func TestComparePinpointsChangedPath(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.zip")
	second := filepath.Join(t.TempDir(), "second.zip")
	writeZIPFixture(t, first, []fixtureEntry{{name: "config/app.json", body: `{"safe":true}`}})
	writeZIPFixture(t, second, []fixtureEntry{{name: "config/app.json", body: `{"safe":false}`}})
	left, _ := Inspect(first)
	right, _ := Inspect(second)
	comparison := Compare(left, right)
	if comparison.Classification != "content_changed" || len(comparison.Modified) != 1 {
		t.Fatalf("unexpected comparison: %#v", comparison)
	}
	if comparison.Modified[0].Path != "config/app.json" {
		t.Fatalf("wrong changed path: %s", comparison.Modified[0].Path)
	}
}

func TestCompareTreatsExplicitDirectoriesAsPackaging(t *testing.T) {
	first := filepath.Join(t.TempDir(), "with-directory.zip")
	second := filepath.Join(t.TempDir(), "without-directory.zip")
	writeZIPFixture(t, first, []fixtureEntry{
		{name: "config/"},
		{name: "config/app.json", body: `{"safe":true}`},
	})
	writeZIPFixture(t, second, []fixtureEntry{{name: "config/app.json", body: `{"safe":true}`}})
	left, err := Inspect(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Inspect(second)
	if err != nil {
		t.Fatal(err)
	}
	comparison := Compare(left, right)
	if comparison.Classification != "metadata_only" || !comparison.DirectoriesChanged {
		t.Fatalf("directory encoding should be packaging-only: %#v", comparison)
	}
	if len(comparison.Added) != 0 || len(comparison.Removed) != 0 {
		t.Fatalf("directory records leaked into payload changes: %#v", comparison)
	}
}

func TestCompareIgnoresChangedReleaseRoot(t *testing.T) {
	first := filepath.Join(t.TempDir(), "v1.zip")
	second := filepath.Join(t.TempDir(), "v2.zip")
	writeZIPFixture(t, first, []fixtureEntry{
		{name: "project-1.0/"},
		{name: "project-1.0/README.md", body: "old"},
		{name: "project-1.0/config/app.json", body: `{"safe":true}`},
	})
	writeZIPFixture(t, second, []fixtureEntry{
		{name: "project-1.1/"},
		{name: "project-1.1/README.md", body: "new"},
		{name: "project-1.1/config/app.json", body: `{"safe":true}`},
	})
	left, err := Inspect(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Inspect(second)
	if err != nil {
		t.Fatal(err)
	}
	comparison := Compare(left, right)
	if comparison.Classification != "content_changed" || len(comparison.Modified) != 1 {
		t.Fatalf("expected one real change below release root: %#v", comparison)
	}
	if comparison.Modified[0].Path != "README.md" {
		t.Fatalf("release root leaked into changed path: %#v", comparison.Modified)
	}
	if !slices.Equal(comparison.StrippedRoots, []string{"project-1.0", "project-1.1"}) {
		t.Fatalf("stripped roots not recorded: %#v", comparison.StrippedRoots)
	}
}

func TestSafeArchivePathRejectsPortableAbsoluteAndTerminalControlPaths(t *testing.T) {
	for _, name := range []string{"C:/escape", "logs/\x1b[31mred"} {
		if _, err := safeArchivePath(name); err == nil {
			t.Fatalf("expected unsafe path rejection for %q", name)
		}
	}
}

func TestInspectRejectsTraversal(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "unsafe.tar")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(f)
	body := []byte("escape")
	if err := w.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Inspect(filename)
	if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestInspectRejectsNonDirectoryPathAncestor(t *testing.T) {
	for _, test := range []struct {
		name      string
		parent    string
		child     string
		wantError string
	}{
		{name: "exact", parent: "a", child: "a/b", wantError: "nested below file"},
		{name: "case-folded component", parent: "A", child: "a/b", wantError: "case-colliding archive path components"},
	} {
		t.Run(test.name, func(t *testing.T) {
			zipPath := filepath.Join(t.TempDir(), "conflict.zip")
			writeZIPFixture(t, zipPath, []fixtureEntry{
				{name: test.parent, body: "file"},
				{name: test.child, body: "nested"},
			})
			if _, err := Inspect(zipPath); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ZIP path graph conflict was accepted: %v", err)
			}

			tarPath := filepath.Join(t.TempDir(), "conflict.tar")
			f, err := os.Create(tarPath)
			if err != nil {
				t.Fatal(err)
			}
			w := tar.NewWriter(f)
			for _, entry := range []struct {
				name string
				body string
			}{{test.parent, "file"}, {test.child, "nested"}} {
				if err := w.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.body))}); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(w, entry.body); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Inspect(tarPath); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("TAR path graph conflict was accepted: %v", err)
			}
		})
	}
}

func TestValidatePathGraphHandlesDeepPathsLinearly(t *testing.T) {
	components := make([]string, 2000)
	for index := range components {
		components[index] = "a"
	}
	deepPath := strings.Join(components, "/")
	entries := []Entry{
		{Path: deepPath, Kind: "file"},
		{Path: deepPath + "/child", Kind: "file"},
	}
	if err := validatePathGraph(entries); err == nil || !strings.Contains(err.Error(), "nested below file") {
		t.Fatalf("deep ancestor conflict was accepted: %v", err)
	}
}

func TestInspectRejectsMalformedArchive(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "broken.tar")
	mustWrite(t, filename, "not an archive")
	if _, err := Inspect(filename); err == nil {
		t.Fatal("expected malformed archive error")
	}
}

func TestInspectRejectsZIPSpecialFileModes(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"fifo":   os.ModeNamedPipe | 0o644,
		"socket": os.ModeSocket | 0o644,
		"device": os.ModeDevice | 0o644,
	} {
		t.Run(name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), name+".zip")
			writeZIPFixture(t, filename, []fixtureEntry{{name: name, mode: mode}})
			if _, err := Inspect(filename); err == nil || !strings.Contains(err.Error(), "unsupported zip entry type") {
				t.Fatalf("accepted ZIP %s entry: %v", name, err)
			}
		})
	}
}

func TestInspectRejectsEveryTruncatedGZIPPrefixAndBadChecksum(t *testing.T) {
	complete := fuzzTARBytes("file.txt", []byte("payload"), 0o644, true)
	for cutoff := 0; cutoff < len(complete); cutoff++ {
		filename := filepath.Join(t.TempDir(), "truncated.tar.gz")
		if err := os.WriteFile(filename, complete[:cutoff], 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(filename); err == nil {
			t.Fatalf("accepted GZIP prefix of %d/%d bytes", cutoff, len(complete))
		}
	}

	corrupt := append([]byte(nil), complete...)
	corrupt[len(corrupt)-8] ^= 0xff
	filename := filepath.Join(t.TempDir(), "bad-checksum.tar.gz")
	if err := os.WriteFile(filename, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(filename); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("accepted bad GZIP checksum: %v", err)
	}
}

func TestInspectBoundsExpandedGZIPTrailer(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(make([]byte, 2<<20)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "trailing-bomb.tar.gz")
	if err := os.WriteFile(filename, compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	limits := archiveLimits{entries: 8, entrySize: 1024, totalSize: 4096}
	if _, err := inspectWithLimits(filename, limits); err == nil || !strings.Contains(err.Error(), "expanded tar stream exceeds") {
		t.Fatalf("expanded GZIP trailer was not bounded: %v", err)
	}
}

func TestInspectBoundsRawArchiveBytesBeforeParsing(t *testing.T) {
	limits := archiveLimits{entries: 1, entrySize: 1024, totalSize: 1024}
	limit, err := expandedTARLimit(limits)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "oversized.zip")
	if err := os.WriteFile(filename, make([]byte, limit+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectWithLimits(filename, limits); err == nil || !strings.Contains(err.Error(), "archive file exceeds") {
		t.Fatalf("oversized raw archive was not rejected before parsing: %v", err)
	}
}

func TestInspectIgnoresGlobalPAXMetadataRecord(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "global-pax.tar")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(f)
	if err := w.WriteHeader(&tar.Header{
		Name:     "pax_global_header",
		Typeflag: tar.TypeXGlobalHeader,
		PAXRecords: map[string]string{
			"comment": "packaging metadata",
		},
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte("release")
	if err := w.WriteHeader(&tar.Header{Name: "README.txt", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Inspect(filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 1 || snapshot.Entries[0].Path != "README.txt" {
		t.Fatalf("global metadata leaked into payload: %#v", snapshot.Entries)
	}
}

func TestPackRejectsSymbolicLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation usually requires an elevated token or developer mode")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "target"), "target")
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := Pack(root, filepath.Join(t.TempDir(), "out.tar"), "tar")
	if err == nil || !strings.Contains(err.Error(), "symbolic links are rejected") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestPackRejectsOutputInsideSourceAndOverwrite(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "file.txt"), "safe")
	inside := filepath.Join(root, "release.tar")
	if _, err := Pack(root, inside, "tar"); err == nil || !strings.Contains(err.Error(), "outside the source") {
		t.Fatalf("expected output-inside-source rejection, got %v", err)
	}

	outside := filepath.Join(t.TempDir(), "release.tar")
	mustWrite(t, outside, "existing")
	if _, err := Pack(root, outside, "tar"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected overwrite rejection, got %v", err)
	}
}

func TestPackRejectsCaseVariedPathComponentsWithoutPublishing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the default Windows filesystem cannot create this collision fixture")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "A", "x.txt"), "first")
	mustWrite(t, filepath.Join(root, "a", "y.txt"), "second")
	output := filepath.Join(t.TempDir(), "release.tar")
	if _, err := Pack(root, output, "tar"); err == nil || !strings.Contains(err.Error(), "case-colliding") {
		t.Fatalf("case-varied components were accepted: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("failed pack left a published destination: %v", err)
	}
}

func TestPublishFileCannotReplaceRacingDestination(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "temporary")
	destination := filepath.Join(root, "release.tar")
	mustWrite(t, source, "new archive")
	mustWrite(t, destination, "existing archive")
	if err := publishFile(source, destination); err == nil {
		t.Fatal("expected exclusive publication to fail")
	}
	if body := string(mustRead(t, destination)); body != "existing archive" {
		t.Fatalf("destination was replaced: %q", body)
	}
	if body := string(mustRead(t, source)); body != "new archive" {
		t.Fatalf("temporary output was lost: %q", body)
	}
}

type fixtureEntry struct {
	name    string
	body    string
	modTime time.Time
	mode    os.FileMode
}

type modeFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (info modeFileInfo) Mode() os.FileMode { return info.mode }

func writeZIPFixture(t *testing.T, filename string, entries []fixtureEntry) {
	t.Helper()
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		if !entry.modTime.IsZero() {
			header.SetModTime(entry.modTime)
		}
		mode := entry.mode
		if mode == 0 {
			if strings.HasSuffix(entry.name, "/") {
				mode = os.ModeDir | 0o755
			} else {
				mode = 0o644
			}
		}
		header.SetMode(mode)
		part, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, filename, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
