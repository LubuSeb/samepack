package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LubuSeb/samepack/internal/archiveio"
)

func TestRunRecordThenVerifyWithoutOriginalArchive(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	mustWriteCLI(t, filepath.Join(source, "README.md"), "hello")
	mustWriteCLI(t, filepath.Join(source, "config", "app.json"), `{"safe":true}`)
	zipArchive := filepath.Join(t.TempDir(), "release.zip")
	tarArchive := filepath.Join(t.TempDir(), "release.tar.gz")
	if _, err := archiveio.Pack(source, zipArchive, "zip"); err != nil {
		t.Fatal(err)
	}
	if _, err := archiveio.Pack(source, tarArchive, "tar.gz"); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "release.samepack.json")
	var recordOut, recordErr bytes.Buffer
	if code := run([]string{"record", "--output", manifest, zipArchive}, &recordOut, &recordErr); code != 0 {
		t.Fatalf("record failed with %d: %s", code, recordErr.String())
	}
	if !strings.Contains(recordOut.String(), "RECORDED") || !strings.Contains(recordOut.String(), "commit or sign") {
		t.Fatalf("record receipt is incomplete: %s", recordOut.String())
	}
	if err := os.Remove(zipArchive); err != nil {
		t.Fatal(err)
	}
	var verifyOut, verifyErr bytes.Buffer
	if code := run([]string{"verify", manifest, tarArchive}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify failed with %d: %s", code, verifyErr.String())
	}
	if !strings.Contains(verifyOut.String(), "PAYLOAD VERIFIED") || !strings.Contains(verifyOut.String(), "archive bytes differ") {
		t.Fatalf("verification did not explain the result: %s", verifyOut.String())
	}
}

func TestRunPackDisclosesDefaultModePolicy(t *testing.T) {
	source := t.TempDir()
	mustWriteCLI(t, filepath.Join(source, "file.txt"), "payload")
	output := filepath.Join(t.TempDir(), "release.tar")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pack", "--output", output, source}, &stdout, &stderr); code != 0 {
		t.Fatalf("pack failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "normalized regular files to mode 0644") ||
		!strings.Contains(stderr.String(), "--preserve-executable") {
		t.Fatalf("mode policy was not disclosed: %q", stderr.String())
	}
}

func TestRunVerifyJSONIsValidOnMismatchAndExitsThree(t *testing.T) {
	leftSource := filepath.Join(t.TempDir(), "source")
	rightSource := filepath.Join(t.TempDir(), "source")
	mustWriteCLI(t, filepath.Join(leftSource, "config.json"), `{"safe":true}`)
	mustWriteCLI(t, filepath.Join(rightSource, "config.json"), `{"safe":false}`)
	leftArchive := filepath.Join(t.TempDir(), "left.zip")
	rightArchive := filepath.Join(t.TempDir(), "right.tar.gz")
	if _, err := archiveio.Pack(leftSource, leftArchive, "zip"); err != nil {
		t.Fatal(err)
	}
	if _, err := archiveio.Pack(rightSource, rightArchive, "tar.gz"); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "baseline.json")
	if code := run([]string{"record", "--output", manifest, leftArchive}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("record failed with %d", code)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "--json", manifest, rightArchive}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("expected exit 3, got %d: %s", code, stderr.String())
	}
	var report verifyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("mismatch JSON is invalid: %v\n%s", err, stdout.String())
	}
	if len(report.Results) != 1 || report.Results[0].Match || len(report.Results[0].Modified) != 1 {
		t.Fatalf("mismatch JSON lost diagnostics: %#v", report)
	}
}

func TestRunCompareExecutableChangeExitsThree(t *testing.T) {
	left := filepath.Join(t.TempDir(), "left.zip")
	right := filepath.Join(t.TempDir(), "right.zip")
	writeModeZIP(t, left, 0o644)
	writeModeZIP(t, right, 0o755)
	var stdout, stderr bytes.Buffer
	code := run([]string{"compare", left, right}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("expected behavior mismatch exit 3, got %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "BEHAVIOR CHANGED") || !strings.Contains(stdout.String(), "! run.sh") {
		t.Fatalf("behavior change is not actionable: %s", stdout.String())
	}
}

func TestRunVerifyDoesNotEmitPartialSuccessOnProcessingError(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	mustWriteCLI(t, filepath.Join(source, "file.txt"), "same")
	archive := filepath.Join(t.TempDir(), "release.zip")
	if _, err := archiveio.Pack(source, archive, "zip"); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "baseline.json")
	if code := run([]string{"record", "--output", manifest, archive}, io.Discard, io.Discard); code != 0 {
		t.Fatal("record failed")
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", manifest, archive, filepath.Join(t.TempDir(), "missing.zip")}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("expected an operational failure without partial report: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestEveryCommandHelpExitsZero(t *testing.T) {
	for _, command := range []string{"record", "verify", "pack", "compare", "inspect"} {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{command, "--help"}, &stdout, &stderr); code != 0 {
				t.Fatalf("%s --help exited %d: %s", command, code, stderr.String())
			}
			if stdout.Len() == 0 && stderr.Len() == 0 {
				t.Fatalf("%s --help printed nothing", command)
			}
		})
	}
}

func TestRunCompareUsesExitThreeForChangedContent(t *testing.T) {
	leftSource := filepath.Join(t.TempDir(), "source")
	rightSource := filepath.Join(t.TempDir(), "source")
	mustWriteCLI(t, filepath.Join(leftSource, "config.json"), `{"safe":true}`)
	mustWriteCLI(t, filepath.Join(rightSource, "config.json"), `{"safe":false}`)
	leftArchive := filepath.Join(t.TempDir(), "left.tar.gz")
	rightArchive := filepath.Join(t.TempDir(), "right.tar.gz")
	if _, err := archiveio.Pack(leftSource, leftArchive, "tar.gz"); err != nil {
		t.Fatal(err)
	}
	if _, err := archiveio.Pack(rightSource, rightArchive, "tar.gz"); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"compare", leftArchive, rightArchive}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("expected exit 3, got %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "~ config.json") {
		t.Fatalf("changed path missing from output: %s", stdout.String())
	}
}

func TestRunPackDefaultsOutsideSource(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "release")
	mustWriteCLI(t, filepath.Join(source, "README.txt"), "hello")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"pack", source}, &stdout, &stderr); code != 0 {
		t.Fatalf("pack failed with %d: %s", code, stderr.String())
	}
	expected := filepath.Join(parent, "release.samepack.tar.gz")
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("default output was not created beside source: %v", err)
	}
	if strings.Contains(stdout.String(), filepath.Join(source, "release.samepack.tar.gz")) {
		t.Fatal("default output was placed inside source")
	}
}

func TestPrintComparisonBoundsLargeHumanOutput(t *testing.T) {
	comparison := archiveio.Comparison{
		Classification: "content_changed",
		Added:          []string{"a", "b"},
		Removed:        []string{"c"},
	}
	var output bytes.Buffer
	printComparison(&output, comparison, 2)
	if strings.Contains(output.String(), "- c") {
		t.Fatalf("output exceeded change limit: %s", output.String())
	}
	if !strings.Contains(output.String(), "1 more changed path") {
		t.Fatalf("truncation was not explained: %s", output.String())
	}
}

func mustWriteCLI(t *testing.T, filename, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeModeZIP(t *testing.T, filename string, mode os.FileMode) {
	t.Helper()
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	header := &zip.FileHeader{Name: "run.sh", Method: zip.Store}
	header.SetMode(mode)
	part, err := w.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "echo hi"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
