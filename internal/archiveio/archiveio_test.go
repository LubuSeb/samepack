package archiveio

import (
	"archive/tar"
	"archive/zip"
	"bytes"
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

func TestInspectRejectsMalformedArchive(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "broken.tar")
	mustWrite(t, filename, "not an archive")
	if _, err := Inspect(filename); err == nil {
		t.Fatal("expected malformed archive error")
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

type fixtureEntry struct {
	name    string
	body    string
	modTime time.Time
}

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
		header.SetMode(0o644)
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
