// Command corpusproof independently reruns Samepack's committed GitHub corpus.
// It intentionally uses only the Go standard library and Samepack's archive
// inspection package.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/LubuSeb/samepack/internal/archiveio"
)

const (
	receiptSchema  = "samepack-corpus-v1"
	maxReceiptSize = int64(8 << 20)
)

type receipt struct {
	Schema               string   `json:"schema"`
	GeneratedAtUTC       string   `json:"generated_at_utc"`
	SamepackVersion      string   `json:"samepack_version"`
	GoVersion            string   `json:"go_version"`
	ImplementationCommit string   `json:"implementation_commit,omitempty"`
	ReverifiedAtUTC      string   `json:"reverified_at_utc,omitempty"`
	Pairs                int      `json:"pairs"`
	Archives             int      `json:"archives"`
	TotalCompressedBytes int64    `json:"total_compressed_bytes"`
	AllOuterHashesDiffer bool     `json:"all_outer_hashes_differ"`
	AllPortableMatches   bool     `json:"all_portable_matches"`
	Results              []result `json:"results"`
}

type result struct {
	Repository     string `json:"repository"`
	Commit         string `json:"commit"`
	CommitURL      string `json:"commit_url"`
	ZIPBytes       int64  `json:"zip_bytes"`
	ZIPSHA256      string `json:"zip_sha256"`
	TarGZBytes     int64  `json:"tar_gz_bytes"`
	TarGZSHA256    string `json:"tar_gz_sha256"`
	PayloadPaths   int    `json:"payload_paths"`
	PayloadBytes   int64  `json:"payload_bytes"`
	PayloadSHA256  string `json:"payload_sha256"`
	PortableSHA256 string `json:"portable_sha256"`
	Match          bool   `json:"match"`
	ElapsedMS      int64  `json:"elapsed_ms"`
}

type artifactSpec struct {
	url    string
	path   string
	size   int64
	sha256 string
}

type observedSide struct {
	URL            string `json:"url"`
	ArtifactBytes  int64  `json:"artifact_bytes"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	PayloadPaths   int    `json:"payload_paths"`
	PayloadBytes   int64  `json:"payload_bytes"`
	PayloadSHA256  string `json:"payload_sha256"`
	PortableSHA256 string `json:"portable_sha256"`
}

type observedResult struct {
	Repository string       `json:"repository"`
	Commit     string       `json:"commit"`
	ZIP        observedSide `json:"zip"`
	TarGZ      observedSide `json:"tar_gz"`
	Match      bool         `json:"match"`
	Error      string       `json:"error,omitempty"`
}

type rerunReceipt struct {
	Schema          string           `json:"schema"`
	GeneratedAtUTC  string           `json:"generated_at_utc"`
	SourceSchema    string           `json:"source_schema"`
	SourceCommit    string           `json:"source_implementation_commit,omitempty"`
	DeclaredPairs   int              `json:"declared_pairs"`
	SelectedPairs   int              `json:"selected_pairs"`
	PassedPairs     int              `json:"passed_pairs"`
	AllSelectedPass bool             `json:"all_selected_pass"`
	Results         []observedResult `json:"results"`
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("corpusproof", flag.ContinueOnError)
	flags.SetOutput(stderr)
	receiptPath := flags.String("receipt", "CORPUS.json", "path to the corpus receipt")
	cachePath := flags.String("cache", filepath.Join(os.TempDir(), "samepack-corpus-proof"), "archive cache directory")
	limit := flags.Int("limit", 0, "maximum pairs to run (0 runs all)")
	outputPath := flags.String("output", "", "optional new path for a machine-readable rerun receipt")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "corpusproof: unexpected positional arguments")
		return 2
	}
	if *limit < 0 {
		fmt.Fprintln(stderr, "corpusproof: -limit cannot be negative")
		return 2
	}
	if strings.TrimSpace(*cachePath) == "" {
		fmt.Fprintln(stderr, "corpusproof: -cache cannot be empty")
		return 2
	}

	receipt, err := readReceipt(*receiptPath)
	if err != nil {
		fmt.Fprintf(stderr, "corpusproof: %v\n", err)
		return 1
	}
	selected := receipt.Results
	if *limit > 0 && *limit < len(selected) {
		selected = selected[:*limit]
	}
	fmt.Fprintf(stdout, "CORPUS declared=%d selected=%d\n", receipt.Pairs, len(selected))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := &http.Client{Timeout: 30 * time.Minute}
	passed := 0
	var paths int
	var payloadBytes, compressedBytes int64
	observed := make([]observedResult, 0, len(selected))
	for index, item := range selected {
		proof, err := provePair(ctx, client, *cachePath, item)
		if err != nil {
			fmt.Fprintf(stderr, "FAIL %s@%s: %v\n", item.Repository, shortCommit(item.Commit), err)
			observed = append(observed, observedResult{
				Repository: item.Repository,
				Commit:     item.Commit,
				ZIP:        proof.ZIP,
				TarGZ:      proof.TarGZ,
				Error:      err.Error(),
			})
			continue
		}
		passed++
		observed = append(observed, proof)
		paths += item.PayloadPaths
		payloadBytes += item.PayloadBytes
		compressedBytes += item.ZIPBytes + item.TarGZBytes
		fmt.Fprintf(stdout, "PASS %d/%d %s@%s zip[payload=%s root=%s] tar.gz[payload=%s root=%s] paths=%d bytes=%d\n",
			index+1, len(selected), item.Repository, shortCommit(item.Commit),
			shortDigest(proof.ZIP.PayloadSHA256), shortDigest(proof.ZIP.PortableSHA256),
			shortDigest(proof.TarGZ.PayloadSHA256), shortDigest(proof.TarGZ.PortableSHA256),
			item.PayloadPaths, item.PayloadBytes)
	}
	allPassed := passed == len(selected)
	if *outputPath != "" {
		machineReceipt := rerunReceipt{
			Schema:          "samepack-corpus-proof-v1",
			GeneratedAtUTC:  time.Now().UTC().Format(time.RFC3339),
			SourceSchema:    receipt.Schema,
			SourceCommit:    receipt.ImplementationCommit,
			DeclaredPairs:   receipt.Pairs,
			SelectedPairs:   len(selected),
			PassedPairs:     passed,
			AllSelectedPass: allPassed,
			Results:         observed,
		}
		if err := writeRerunReceipt(*outputPath, machineReceipt); err != nil {
			fmt.Fprintf(stderr, "corpusproof: write rerun receipt: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "RECEIPT %s\n", *outputPath)
	}
	if !allPassed {
		fmt.Fprintf(stderr, "FAIL total: %d/%d pairs passed\n", passed, len(selected))
		return 1
	}
	fmt.Fprintf(stdout, "PASS total: %d pairs, %d archives, %d compressed bytes, %d paths, %d payload bytes\n",
		passed, passed*2, compressedBytes, paths, payloadBytes)
	return 0
}

func readReceipt(filename string) (receipt, error) {
	f, err := os.Open(filename)
	if err != nil {
		return receipt{}, fmt.Errorf("open receipt: %w", err)
	}
	defer f.Close()

	limited := &io.LimitedReader{R: f, N: maxReceiptSize + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var parsed receipt
	if err := decoder.Decode(&parsed); err != nil {
		return receipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return receipt{}, errors.New("decode receipt: trailing JSON value")
		}
		return receipt{}, fmt.Errorf("decode receipt: trailing data: %w", err)
	}
	if limited.N == 0 {
		return receipt{}, fmt.Errorf("receipt exceeds %d bytes", maxReceiptSize)
	}
	if err := validateReceipt(parsed); err != nil {
		return receipt{}, fmt.Errorf("validate receipt: %w", err)
	}
	return parsed, nil
}

func validateReceipt(parsed receipt) error {
	if parsed.Schema != receiptSchema {
		return fmt.Errorf("unsupported schema %q", parsed.Schema)
	}
	if parsed.GeneratedAtUTC == "" {
		return errors.New("generated_at_utc is empty")
	}
	if _, err := time.Parse(time.RFC3339, parsed.GeneratedAtUTC); err != nil {
		return fmt.Errorf("generated_at_utc: %w", err)
	}
	if parsed.SamepackVersion == "" || parsed.GoVersion == "" {
		return errors.New("samepack_version and go_version must be non-empty")
	}
	if parsed.ImplementationCommit != "" &&
		(len(parsed.ImplementationCommit) != 40 || !validLowerHex(parsed.ImplementationCommit)) {
		return errors.New("implementation_commit must be 40 lowercase hexadecimal characters when set")
	}
	if parsed.ReverifiedAtUTC != "" {
		if _, err := time.Parse(time.RFC3339, parsed.ReverifiedAtUTC); err != nil {
			return fmt.Errorf("reverified_at_utc: %w", err)
		}
	}
	if parsed.Pairs != len(parsed.Results) {
		return fmt.Errorf("pairs is %d, want %d", parsed.Pairs, len(parsed.Results))
	}
	if len(parsed.Results) == 0 {
		return errors.New("results is empty")
	}
	if parsed.Archives != len(parsed.Results)*2 {
		return fmt.Errorf("archives is %d, want %d", parsed.Archives, len(parsed.Results)*2)
	}
	if !parsed.AllOuterHashesDiffer {
		return errors.New("all_outer_hashes_differ is false")
	}
	if !parsed.AllPortableMatches {
		return errors.New("all_portable_matches is false")
	}

	seen := make(map[string]struct{}, len(parsed.Results))
	var compressed int64
	for index, item := range parsed.Results {
		name := fmt.Sprintf("result %d", index)
		if err := validateRepository(item.Repository); err != nil {
			return fmt.Errorf("%s repository: %w", name, err)
		}
		if !validCommit(item.Commit) {
			return fmt.Errorf("%s commit must be 40 or 64 lowercase hexadecimal characters", name)
		}
		key := item.Repository + "@" + item.Commit
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate result %q", key)
		}
		seen[key] = struct{}{}
		wantCommitURL, _, _, err := githubURLs(item.Repository, item.Commit)
		if err != nil {
			return fmt.Errorf("%s URLs: %w", name, err)
		}
		if item.CommitURL != wantCommitURL {
			return fmt.Errorf("%s commit_url is %q, want %q", name, item.CommitURL, wantCommitURL)
		}
		if item.ZIPBytes <= 0 || item.TarGZBytes <= 0 {
			return fmt.Errorf("%s archive sizes must be positive", name)
		}
		if !validDigest(item.ZIPSHA256) || !validDigest(item.TarGZSHA256) {
			return fmt.Errorf("%s archive SHA-256 values must be lowercase hexadecimal", name)
		}
		if item.ZIPSHA256 == item.TarGZSHA256 {
			return fmt.Errorf("%s outer archive hashes are equal", name)
		}
		if item.PayloadPaths <= 0 || item.PayloadBytes < 0 {
			return fmt.Errorf("%s payload counts are invalid", name)
		}
		if !validDigest(item.PayloadSHA256) || !validDigest(item.PortableSHA256) {
			return fmt.Errorf("%s payload SHA-256 values must be lowercase hexadecimal", name)
		}
		if !item.Match {
			return fmt.Errorf("%s match is false", name)
		}
		if item.ElapsedMS < 0 {
			return fmt.Errorf("%s elapsed_ms is negative", name)
		}
		if compressed > math.MaxInt64-item.ZIPBytes-item.TarGZBytes {
			return errors.New("total compressed size overflows int64")
		}
		compressed += item.ZIPBytes + item.TarGZBytes
	}
	if parsed.TotalCompressedBytes != compressed {
		return fmt.Errorf("total_compressed_bytes is %d, want %d", parsed.TotalCompressedBytes, compressed)
	}
	return nil
}

func validateRepository(repository string) error {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || !validRepositoryPart(parts[0]) || !validRepositoryPart(parts[1]) {
		return fmt.Errorf("%q is not an owner/repository name", repository)
	}
	return nil
}

func validRepositoryPart(value string) bool {
	if value == "" || len(value) > 100 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validCommit(commit string) bool {
	return (len(commit) == 40 || len(commit) == 64) && validLowerHex(commit)
}

func validDigest(digest string) bool {
	return len(digest) == sha256.Size*2 && validLowerHex(digest)
}

func validLowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func githubURLs(repository, commit string) (commitURL, zipURL, tarGZURL string, err error) {
	if err := validateRepository(repository); err != nil {
		return "", "", "", err
	}
	if !validCommit(commit) {
		return "", "", "", errors.New("invalid commit")
	}
	parts := strings.Split(repository, "/")
	base := url.URL{Scheme: "https", Host: "github.com", Path: "/" + parts[0] + "/" + parts[1]}
	commitURL = base.String() + "/commit/" + commit
	archiveBase := base.String() + "/archive/" + commit
	return commitURL, archiveBase + ".zip", archiveBase + ".tar.gz", nil
}

func provePair(ctx context.Context, client httpDoer, cacheDirectory string, item result) (observedResult, error) {
	proof := observedResult{Repository: item.Repository, Commit: item.Commit}
	_, zipURL, tarGZURL, err := githubURLs(item.Repository, item.Commit)
	if err != nil {
		return proof, err
	}
	proof.ZIP.URL = zipURL
	proof.TarGZ.URL = tarGZURL
	zipSpec := artifactSpec{
		url:    zipURL,
		path:   cacheFile(cacheDirectory, item.Repository, item.Commit, "zip"),
		size:   item.ZIPBytes,
		sha256: item.ZIPSHA256,
	}
	tarSpec := artifactSpec{
		url:    tarGZURL,
		path:   cacheFile(cacheDirectory, item.Repository, item.Commit, "tar.gz"),
		size:   item.TarGZBytes,
		sha256: item.TarGZSHA256,
	}
	zipPath, err := ensureArtifact(ctx, client, zipSpec)
	if err != nil {
		return proof, fmt.Errorf("ZIP: %w", err)
	}
	tarPath, err := ensureArtifact(ctx, client, tarSpec)
	if err != nil {
		return proof, fmt.Errorf("TAR.GZ: %w", err)
	}

	zipSnapshot, err := archiveio.Inspect(zipPath)
	if err != nil {
		return proof, fmt.Errorf("inspect ZIP: %w", err)
	}
	if zipSnapshot.Format != "zip" || zipSnapshot.ByteSHA256 != item.ZIPSHA256 {
		return proof, fmt.Errorf("ZIP inspection identity mismatch")
	}
	manifest, err := archiveio.CreateManifest(zipSnapshot, archiveio.WrapperNone)
	if err != nil {
		return proof, fmt.Errorf("record ZIP: %w", err)
	}
	proof.ZIP = observedSide{
		URL:            zipURL,
		ArtifactBytes:  item.ZIPBytes,
		ArtifactSHA256: zipSnapshot.ByteSHA256,
		PayloadPaths:   len(manifest.Entries),
		PayloadBytes:   manifestBytes(manifest),
		PayloadSHA256:  manifest.PayloadSHA256,
		PortableSHA256: manifest.RootSHA256,
	}
	if err := requireManifestReceipt(manifest, item); err != nil {
		return proof, fmt.Errorf("ZIP receipt mismatch: %w", err)
	}

	tarSnapshot, err := archiveio.Inspect(tarPath)
	if err != nil {
		return proof, fmt.Errorf("inspect TAR.GZ: %w", err)
	}
	if tarSnapshot.Format != "tar.gz" || tarSnapshot.ByteSHA256 != item.TarGZSHA256 {
		return proof, fmt.Errorf("TAR.GZ inspection identity mismatch")
	}
	verification, err := archiveio.VerifyManifest(manifest, tarSnapshot)
	if err != nil {
		return proof, fmt.Errorf("verify TAR.GZ: %w", err)
	}
	proof.TarGZ = observedSide{
		URL:            tarGZURL,
		ArtifactBytes:  item.TarGZBytes,
		ArtifactSHA256: tarSnapshot.ByteSHA256,
		PayloadPaths:   verification.PayloadPaths,
		PayloadBytes:   verification.PayloadBytes,
		PayloadSHA256:  verification.ObservedPayloadSHA,
		PortableSHA256: verification.ObservedRootSHA256,
	}
	if !verification.Match || verification.Classification != "verified" ||
		!verification.PayloadIdentical || !verification.PortableIdentical {
		return proof, fmt.Errorf("TAR.GZ did not verify: classification=%s", verification.Classification)
	}
	if verification.PayloadPaths != item.PayloadPaths || verification.PayloadBytes != item.PayloadBytes {
		return proof, fmt.Errorf("TAR.GZ payload is %d paths/%d bytes, want %d/%d",
			verification.PayloadPaths, verification.PayloadBytes, item.PayloadPaths, item.PayloadBytes)
	}
	if verification.ObservedPayloadSHA != item.PayloadSHA256 ||
		verification.ObservedRootSHA256 != item.PortableSHA256 {
		return proof, errors.New("TAR.GZ payload or portable root differs from receipt")
	}
	proof.Match = true
	return proof, nil
}

func requireManifestReceipt(manifest archiveio.Manifest, item result) error {
	if len(manifest.Entries) != item.PayloadPaths {
		return fmt.Errorf("payload has %d paths, want %d", len(manifest.Entries), item.PayloadPaths)
	}
	var size int64
	for _, entry := range manifest.Entries {
		if size > math.MaxInt64-entry.Size {
			return errors.New("payload byte count overflows int64")
		}
		size += entry.Size
	}
	if size != item.PayloadBytes {
		return fmt.Errorf("payload has %d bytes, want %d", size, item.PayloadBytes)
	}
	if manifest.PayloadSHA256 != item.PayloadSHA256 {
		return fmt.Errorf("payload SHA-256 is %s, want %s", manifest.PayloadSHA256, item.PayloadSHA256)
	}
	if manifest.RootSHA256 != item.PortableSHA256 {
		return fmt.Errorf("portable SHA-256 is %s, want %s", manifest.RootSHA256, item.PortableSHA256)
	}
	return nil
}

func manifestBytes(manifest archiveio.Manifest) int64 {
	var total int64
	for _, entry := range manifest.Entries {
		total += entry.Size
	}
	return total
}

func writeRerunReceipt(filename string, value rerunReceipt) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".samepack-corpus-proof-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temp.Write(encoded.Bytes()); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempName, absolute); err != nil {
		return fmt.Errorf("publish without overwrite: %w", err)
	}
	return nil
}

func cacheFile(directory, repository, commit, suffix string) string {
	digest := sha256.Sum256([]byte(repository + "\x00" + commit))
	return filepath.Join(directory, hex.EncodeToString(digest[:])+"."+suffix)
}

func ensureArtifact(ctx context.Context, client httpDoer, spec artifactSpec) (string, error) {
	hit, err := cacheLookup(spec.path, spec.size, spec.sha256)
	if err != nil {
		return "", fmt.Errorf("check cache: %w", err)
	}
	if hit {
		return spec.path, nil
	}
	if err := os.MkdirAll(filepath.Dir(spec.path), 0o755); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}
	if err := removeInvalidRegular(spec.path); err != nil {
		return "", err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "samepack-corpusproof/0.2")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %s", response.Status)
	}
	if response.ContentLength >= 0 && response.ContentLength != spec.size {
		return "", fmt.Errorf("Content-Length is %d, want %d", response.ContentLength, spec.size)
	}

	temp, err := os.CreateTemp(filepath.Dir(spec.path), ".samepack-corpus-*")
	if err != nil {
		return "", fmt.Errorf("create temporary archive: %w", err)
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(0o644); err != nil {
		return "", fmt.Errorf("set temporary archive permissions: %w", err)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(response.Body, spec.size+1))
	if err != nil {
		return "", fmt.Errorf("write temporary archive: %w", err)
	}
	if written != spec.size {
		return "", fmt.Errorf("downloaded %d bytes, want %d", written, spec.size)
	}
	gotDigest := hex.EncodeToString(hash.Sum(nil))
	if gotDigest != spec.sha256 {
		return "", fmt.Errorf("download SHA-256 is %s, want %s", gotDigest, spec.sha256)
	}
	if err := temp.Sync(); err != nil {
		return "", fmt.Errorf("sync temporary archive: %w", err)
	}
	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("close temporary archive: %w", err)
	}

	// Another process may have populated this content-address-checked target
	// while the request was running. Prefer its valid copy; otherwise publish
	// the complete temporary file with a same-directory atomic rename.
	if hit, lookupErr := cacheLookup(spec.path, spec.size, spec.sha256); lookupErr != nil {
		return "", fmt.Errorf("recheck cache: %w", lookupErr)
	} else if hit {
		return spec.path, nil
	}
	if err := removeInvalidRegular(spec.path); err != nil {
		return "", err
	}
	if err := os.Rename(tempName, spec.path); err != nil {
		if hit, lookupErr := cacheLookup(spec.path, spec.size, spec.sha256); lookupErr == nil && hit {
			return spec.path, nil
		}
		return "", fmt.Errorf("publish archive: %w", err)
	}
	return spec.path, nil
}

func cacheLookup(filename string, expectedSize int64, expectedSHA256 string) (bool, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("cache path is not a regular file")
	}
	if info.Size() != expectedSize {
		return false, nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer f.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, f)
	if err != nil {
		return false, err
	}
	if written != expectedSize {
		return false, nil
	}
	return hex.EncodeToString(hash.Sum(nil)) == expectedSHA256, nil
}

func removeInvalidRegular(filename string) error {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect invalid cache entry: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to replace non-regular cache path")
	}
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("remove invalid cache entry: %w", err)
	}
	return nil
}

func shortCommit(commit string) string {
	if len(commit) <= 12 {
		return commit
	}
	return commit[:12]
}

func shortDigest(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}
