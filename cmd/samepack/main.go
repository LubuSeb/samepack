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

const version = "0.2.0"

type recordResult struct {
	Manifest       string `json:"manifest"`
	Archive        string `json:"archive"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	PayloadSHA256  string `json:"payload_sha256"`
	RootSHA256     string `json:"root_sha256"`
	PayloadPaths   int    `json:"payload_paths"`
	WrapperPolicy  string `json:"wrapper_policy"`
	StrippedRoot   string `json:"stripped_root,omitempty"`
}

type verifyReport struct {
	Manifest string                   `json:"manifest"`
	Results  []archiveio.Verification `json:"results"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}
	switch args[0] {
	case "record":
		return runRecord(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
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
		if len(args) > 1 {
			return printCommandUsage(args[1], stdout, stderr)
		}
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "samepack: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func runRecord(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "manifest output path (required)")
	stripRoot := flags.Bool("strip-root", false, "ignore one common top-level directory")
	jsonOutput := flags.Bool("json", false, "write a machine-readable command receipt")
	flags.Usage = func() { printRecordUsage(flags.Output()) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "samepack record: expected one archive")
		return 1
	}
	if *output == "" {
		fmt.Fprintln(stderr, "samepack record: --output is required")
		return 1
	}
	archive := flags.Arg(0)
	snapshot, err := archiveio.Inspect(archive)
	if err != nil {
		fmt.Fprintln(stderr, "samepack record:", err)
		return 1
	}
	wrapperPolicy := archiveio.WrapperNone
	if *stripRoot {
		wrapperPolicy = archiveio.WrapperStripSingle
	}
	manifest, err := archiveio.CreateManifest(snapshot, wrapperPolicy)
	if err != nil {
		fmt.Fprintln(stderr, "samepack record:", err)
		return 1
	}
	if err := archiveio.WriteManifest(*output, manifest); err != nil {
		fmt.Fprintln(stderr, "samepack record:", err)
		return 1
	}
	receipt := recordResult{
		Manifest:       *output,
		Archive:        archive,
		ArtifactSHA256: snapshot.ByteSHA256,
		PayloadSHA256:  manifest.PayloadSHA256,
		RootSHA256:     manifest.RootSHA256,
		PayloadPaths:   len(manifest.Entries),
		WrapperPolicy:  wrapperPolicy,
		StrippedRoot:   manifest.Source.StrippedRoot,
	}
	if *jsonOutput {
		return writeJSON(stdout, stderr, receipt)
	}
	fmt.Fprintln(stdout, "RECORDED — portable payload baseline written")
	fmt.Fprintln(stdout, "manifest ", receipt.Manifest)
	fmt.Fprintln(stdout, "archive  ", receipt.Archive)
	fmt.Fprintf(stdout, "paths     %d files/symlinks\n", receipt.PayloadPaths)
	fmt.Fprintf(stdout, "artifact  sha256:%s\n", receipt.ArtifactSHA256)
	fmt.Fprintf(stdout, "payload   sha256:%s\n", receipt.PayloadSHA256)
	fmt.Fprintf(stdout, "portable  sha256:%s\n", receipt.RootSHA256)
	if receipt.StrippedRoot != "" {
		fmt.Fprintf(stdout, "wrapper   ignored %s/\n", receipt.StrippedRoot)
	}
	fmt.Fprintln(stdout, "next      commit or sign the manifest before trusting it")
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "write one machine-readable result")
	maxChanges := flags.Int("max-changes", 50, "maximum changed paths to print per archive; 0 shows all")
	flags.Usage = func() { printVerifyUsage(flags.Output()) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if *maxChanges < 0 {
		fmt.Fprintln(stderr, "samepack verify: --max-changes cannot be negative")
		return 1
	}
	if flags.NArg() < 2 {
		fmt.Fprintln(stderr, "samepack verify: expected a manifest and at least one archive")
		return 1
	}
	manifestPath := flags.Arg(0)
	manifest, err := archiveio.ReadManifest(manifestPath)
	if err != nil {
		fmt.Fprintln(stderr, "samepack verify:", err)
		return 1
	}
	results := make([]archiveio.Verification, 0, flags.NArg()-1)
	for _, archive := range flags.Args()[1:] {
		snapshot, inspectErr := archiveio.Inspect(archive)
		if inspectErr != nil {
			fmt.Fprintf(stderr, "samepack verify: cannot inspect %q: %v\n", archive, inspectErr)
			return 1
		}
		result, verifyErr := archiveio.VerifyManifest(manifest, snapshot)
		if verifyErr != nil {
			fmt.Fprintf(stderr, "samepack verify: cannot verify %q: %v\n", archive, verifyErr)
			return 1
		}
		results = append(results, result)
	}
	if *jsonOutput {
		if code := writeJSON(stdout, stderr, verifyReport{Manifest: manifestPath, Results: results}); code != 0 {
			return code
		}
	} else {
		for index, result := range results {
			if index > 0 {
				fmt.Fprintln(stdout)
			}
			printVerification(stdout, manifestPath, result, *maxChanges)
		}
		if len(results) > 1 {
			matched := 0
			for _, result := range results {
				if result.Match {
					matched++
				}
			}
			fmt.Fprintln(stdout)
			if matched == len(results) {
				fmt.Fprintf(stdout, "VERIFY COMPLETE — %d archives matched\n", matched)
			} else {
				fmt.Fprintf(stdout, "VERIFY FAILED — %d matched, %d mismatched\n", matched, len(results)-matched)
			}
		}
	}
	for _, result := range results {
		if !result.Match {
			return 3
		}
	}
	return 0
}

func runPack(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("pack", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "output archive path")
	format := flags.String("format", "auto", "tar, tar.gz, zip, or auto")
	preserveExecutable := flags.Bool("preserve-executable", false, "preserve executable bits exposed by the source filesystem")
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
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
	snapshot, err := archiveio.PackWithOptions(source, *output, archiveio.PackOptions{
		Format:             *format,
		PreserveExecutable: *preserveExecutable,
	})
	if err != nil {
		fmt.Fprintln(stderr, "samepack pack:", err)
		return 1
	}
	if *jsonOutput {
		if !*preserveExecutable {
			fmt.Fprintln(stderr, "samepack pack: note: normalized regular files to mode 0644; use --preserve-executable to retain source executable status")
		}
		return writeJSON(stdout, stderr, snapshot)
	}
	fmt.Fprintf(stdout, "PACKED %d entries as %s\n", len(snapshot.Entries), snapshot.Format)
	fmt.Fprintf(stdout, "artifact  sha256:%s  %s\n", snapshot.ByteSHA256, snapshot.Archive)
	fmt.Fprintf(stdout, "content   sha256:%s\n", snapshot.ContentSHA256)
	if !*preserveExecutable {
		fmt.Fprintln(stderr, "samepack pack: note: normalized regular files to mode 0644; use --preserve-executable to retain source executable status")
	}
	return 0
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	maxChanges := flags.Int("max-changes", 50, "maximum changed paths to print; 0 shows all")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if *maxChanges < 0 {
		fmt.Fprintln(stderr, "samepack compare: --max-changes cannot be negative")
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
		printComparison(stdout, comparison, *maxChanges)
	}
	if comparison.PortableIdentical {
		return 0
	}
	return 3
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
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

func printComparison(w io.Writer, result archiveio.Comparison, maxChanges int) {
	switch result.Classification {
	case "byte_identical":
		fmt.Fprintln(w, "BYTE IDENTICAL — the archives have the same SHA-256")
	case "metadata_only":
		fmt.Fprintln(w, "PAYLOAD IDENTICAL — paths, bytes, types, and executable status match")
	case "behavior_changed":
		fmt.Fprintf(w, "BEHAVIOR CHANGED — payload bytes match, but %d executable permission(s) differ\n", len(result.BehaviorModified))
	case "content_changed":
		fmt.Fprintf(w, "PAYLOAD CHANGED — %d added, %d removed, %d modified path(s)\n", len(result.Added), len(result.Removed), len(result.Modified))
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
	printed := 0
	canPrint := func() bool { return maxChanges == 0 || printed < maxChanges }
	for _, path := range result.Added {
		if !canPrint() {
			break
		}
		fmt.Fprintln(w, "+", path)
		printed++
	}
	for _, path := range result.Removed {
		if !canPrint() {
			break
		}
		fmt.Fprintln(w, "-", path)
		printed++
	}
	for _, change := range result.Modified {
		if !canPrint() {
			break
		}
		if change.BeforeKind != change.AfterKind {
			fmt.Fprintf(w, "~ %s  kind %s -> %s\n", change.Path, change.BeforeKind, change.AfterKind)
		} else {
			fmt.Fprintf(w, "~ %s  %s -> %s\n", change.Path, shortDigest(change.BeforeSHA256), shortDigest(change.AfterSHA256))
		}
		printed++
	}
	for _, change := range result.BehaviorModified {
		if !canPrint() {
			break
		}
		fmt.Fprintf(w, "! %s  executable %t -> %t\n", change.Path, change.BeforeExecutable, change.AfterExecutable)
		printed++
	}
	totalChanges := len(result.Added) + len(result.Removed) + len(result.Modified) + len(result.BehaviorModified)
	if remaining := totalChanges - printed; remaining > 0 {
		fmt.Fprintf(w, "… %d more changed path(s); rerun with --max-changes 0 to show all\n", remaining)
	}
}

func printVerification(w io.Writer, manifestPath string, result archiveio.Verification, maxChanges int) {
	switch result.Classification {
	case "verified":
		if result.ArtifactSHA256 == result.RecordedArtifactSHA {
			fmt.Fprintf(w, "ARCHIVE VERIFIED — %d payload paths and archive bytes match\n", result.PayloadPaths)
		} else {
			fmt.Fprintf(w, "PAYLOAD VERIFIED — %d paths match despite different archive bytes\n", result.PayloadPaths)
		}
	case "behavior_changed":
		fmt.Fprintf(w, "BEHAVIOR MISMATCH — payload bytes match; %d executable permission(s) changed\n", len(result.ExecutableChanged))
	case "payload_changed":
		fmt.Fprintf(w, "PAYLOAD MISMATCH — %d added, %d removed, %d modified\n", len(result.Added), len(result.Removed), len(result.Modified))
	}
	fmt.Fprintln(w, "manifest ", manifestPath)
	fmt.Fprintln(w, "archive  ", result.Archive)
	fmt.Fprintf(w, "recorded  artifact sha256:%s\n", result.RecordedArtifactSHA)
	fmt.Fprintf(w, "observed  artifact sha256:%s\n", result.ArtifactSHA256)
	if !result.PayloadIdentical {
		fmt.Fprintf(w, "expected  payload sha256:%s\n", result.ExpectedPayloadSHA)
		fmt.Fprintf(w, "observed  payload sha256:%s\n", result.ObservedPayloadSHA)
	} else {
		fmt.Fprintf(w, "payload   sha256:%s\n", result.ObservedPayloadSHA)
	}
	if !result.PortableIdentical {
		fmt.Fprintf(w, "expected  portable sha256:%s\n", result.ExpectedRootSHA256)
		fmt.Fprintf(w, "observed  portable sha256:%s\n", result.ObservedRootSHA256)
	}
	if result.StrippedRoot != "" {
		fmt.Fprintf(w, "wrapper   ignored %s/\n", result.StrippedRoot)
	}
	if result.Match && result.ArtifactSHA256 != result.RecordedArtifactSHA {
		fmt.Fprintln(w, "note      archive bytes differ; payload and executable behavior match")
	}

	printed := 0
	canPrint := func() bool { return maxChanges == 0 || printed < maxChanges }
	for _, name := range result.Added {
		if !canPrint() {
			break
		}
		fmt.Fprintln(w, "+", name)
		printed++
	}
	for _, name := range result.Removed {
		if !canPrint() {
			break
		}
		fmt.Fprintln(w, "-", name)
		printed++
	}
	for _, change := range result.Modified {
		if !canPrint() {
			break
		}
		if change.ExpectedKind != change.ObservedKind {
			fmt.Fprintf(w, "~ %s  kind %s -> %s\n", change.Path, change.ExpectedKind, change.ObservedKind)
		} else {
			fmt.Fprintf(w, "~ %s  %s -> %s\n", change.Path, shortDigest(change.ExpectedSHA256), shortDigest(change.ObservedSHA256))
		}
		printed++
	}
	for _, change := range result.ExecutableChanged {
		if !canPrint() {
			break
		}
		fmt.Fprintf(w, "! %s  executable %t -> %t\n", change.Path, change.ExpectedExecutable, change.ObservedExecutable)
		printed++
	}
	total := len(result.Added) + len(result.Removed) + len(result.Modified) + len(result.ExecutableChanged)
	if remaining := total - printed; remaining > 0 {
		fmt.Fprintf(w, "… %d more changed path(s); use --max-changes 0 to show all\n", remaining)
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
	fmt.Fprintln(w, `samepack — stable payload identity for release archives

Usage:
  samepack record --output FILE [--strip-root] [--json] ARCHIVE
  samepack verify [--json] [--max-changes N] MANIFEST ARCHIVE...
  samepack pack [--output FILE] [--format tar|tar.gz|zip] [--preserve-executable] [--json] DIRECTORY
  samepack compare [--json] [--max-changes N] BEFORE AFTER
  samepack inspect [--json] ARCHIVE
  samepack version

Exit codes:
  0  success, or every portable payload matched
  1  invalid input or processing error
  3  a valid archive contains changed payload or executable behavior`)
}

func printCommandUsage(command string, stdout, stderr io.Writer) int {
	switch command {
	case "record":
		printRecordUsage(stdout)
	case "verify":
		printVerifyUsage(stdout)
	case "pack", "compare", "inspect":
		fmt.Fprintf(stdout, "Run samepack %s --help for options.\n", command)
	default:
		fmt.Fprintf(stderr, "samepack help: unknown command %q\n", command)
		return 1
	}
	return 0
}

func printRecordUsage(w io.Writer) {
	fmt.Fprintln(w, `samepack record — save a trusted portable-payload baseline

Usage:
  samepack record --output FILE [--strip-root] [--json] ARCHIVE

Reads ARCHIVE without writing its entries to disk and creates a versioned JSON
manifest. Existing output files are never replaced.

Options:
  --output FILE  Manifest path (required)
  --strip-root   Ignore one common top-level directory and persist that policy
  --json         Write the command receipt as JSON to stdout

Commit or sign the manifest before treating it as trusted.`)
}

func printVerifyUsage(w io.Writer) {
	fmt.Fprintln(w, `samepack verify — check archives against a recorded portable payload

Usage:
  samepack verify [--json] [--max-changes N] MANIFEST ARCHIVE...

Reads each archive without writing its entries to disk. Different archive bytes
are allowed when paths, payload bytes, types, and executable status still match.

Exit codes:
  0  every portable payload matched
  1  a manifest or archive could not be processed
  3  at least one valid archive did not match`)
}
