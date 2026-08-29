package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LubuSeb/samepack/internal/archiveio"
)

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
