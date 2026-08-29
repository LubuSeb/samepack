package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/LubuSeb/samepack/internal/archiveio"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}
	switch args[0] {
	case "pack":
		return runPack(args[1:], stdout, stderr)
	case "compare":
		return runCompare(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, "samepack", version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "samepack: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func runPack(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("pack", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "output archive path")
	format := flags.String("format", "auto", "tar, tar.gz, zip, or auto")
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "samepack pack: expected one source directory")
		return 1
	}
	source := flags.Arg(0)
	if *output == "" {
		absolute, err := filepath.Abs(source)
		if err != nil {
			fmt.Fprintln(stderr, "samepack pack: resolve source:", err)
			return 1
		}
		base := filepath.Base(filepath.Clean(absolute))
		*output = filepath.Join(filepath.Dir(absolute), base+".samepack.tar.gz")
	}
	snapshot, err := archiveio.Pack(source, *output, *format)
	if err != nil {
		fmt.Fprintln(stderr, "samepack pack:", err)
		return 1
	}
	if *jsonOutput {
		return writeJSON(stdout, stderr, snapshot)
	}
	fmt.Fprintf(stdout, "PACKED %d entries as %s\n", len(snapshot.Entries), snapshot.Format)
	fmt.Fprintf(stdout, "artifact  sha256:%s  %s\n", snapshot.ByteSHA256, snapshot.Archive)
	fmt.Fprintf(stdout, "content   sha256:%s\n", snapshot.ContentSHA256)
	return 0
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	if flags.NArg() != 2 {
		fmt.Fprintln(stderr, "samepack compare: expected two archives")
		return 1
	}
	before, err := archiveio.Inspect(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "samepack compare:", err)
		return 1
	}
	after, err := archiveio.Inspect(flags.Arg(1))
	if err != nil {
		fmt.Fprintln(stderr, "samepack compare:", err)
		return 1
	}
	comparison := archiveio.Compare(before, after)
	if *jsonOutput {
		if code := writeJSON(stdout, stderr, comparison); code != 0 {
			return code
		}
	} else {
		printComparison(stdout, comparison)
	}
	if comparison.ContentIdentical {
		return 0
	}
	return 3
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "samepack inspect: expected one archive")
		return 1
	}
	snapshot, err := archiveio.Inspect(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "samepack inspect:", err)
		return 1
	}
	if *jsonOutput {
		return writeJSON(stdout, stderr, snapshot)
	}
	fmt.Fprintf(stdout, "%s  %d entries\n", strings.ToUpper(snapshot.Format), len(snapshot.Entries))
	fmt.Fprintf(stdout, "artifact  sha256:%s\n", snapshot.ByteSHA256)
	fmt.Fprintf(stdout, "content   sha256:%s\n", snapshot.ContentSHA256)
	for _, entry := range snapshot.Entries {
		fmt.Fprintf(stdout, "%s  %8d  %s  %s\n", entry.Kind, entry.Size, shortDigest(entry.SHA256), entry.Path)
	}
	return 0
}

func printComparison(w io.Writer, result archiveio.Comparison) {
	switch result.Classification {
	case "byte_identical":
		fmt.Fprintln(w, "BYTE IDENTICAL — the archives have the same SHA-256")
	case "metadata_only":
		fmt.Fprintln(w, "CONTENT IDENTICAL — raw bytes differ only in packaging metadata or encoding")
	case "content_changed":
		fmt.Fprintf(w, "CONTENT CHANGED — %d added, %d removed, %d modified path(s)\n", len(result.Added), len(result.Removed), len(result.Modified))
	}
	fmt.Fprintf(w, "before    sha256:%s\n", result.Before.ByteSHA256)
	fmt.Fprintf(w, "after     sha256:%s\n", result.After.ByteSHA256)
	fmt.Fprintf(w, "content   sha256:%s\n", result.Before.ContentSHA256)
	if !result.ContentIdentical {
		fmt.Fprintf(w, "content'  sha256:%s\n", result.After.ContentSHA256)
	}
	for _, reason := range result.Reasons {
		fmt.Fprintln(w, "reason   ", reason)
	}
	for _, path := range result.Added {
		fmt.Fprintln(w, "+", path)
	}
	for _, path := range result.Removed {
		fmt.Fprintln(w, "-", path)
	}
	for _, change := range result.Modified {
		fmt.Fprintf(w, "~ %s  %s -> %s\n", change.Path, shortDigest(change.BeforeSHA256), shortDigest(change.AfterSHA256))
	}
}

func shortDigest(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		fmt.Fprintln(stderr, "samepack: write JSON:", err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `samepack — deterministic release archives and archive forensics

Usage:
  samepack pack [--output FILE] [--format tar|tar.gz|zip] [--json] DIRECTORY
  samepack compare [--json] BEFORE AFTER
  samepack inspect [--json] ARCHIVE
  samepack version

Exit codes:
  0  success, or compared archives have identical content
  1  invalid input or processing error
  3  compared archives contain changed content`)
}
