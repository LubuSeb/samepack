package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateReceipt(t *testing.T) {
	valid := testReceipt()
	if err := validateReceipt(valid); err != nil {
		t.Fatalf("validateReceipt(valid): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*receipt)
		want   string
	}{
		{"schema", func(value *receipt) { value.Schema = "future" }, "unsupported schema"},
		{"pair count", func(value *receipt) { value.Pairs++ }, "pairs is"},
		{"archive count", func(value *receipt) { value.Archives++ }, "archives is"},
		{"implementation commit", func(value *receipt) { value.ImplementationCommit = strings.Repeat("A", 40) }, "implementation_commit"},
		{"reverification time", func(value *receipt) { value.ReverifiedAtUTC = "not-a-time" }, "reverified_at_utc"},
		{"aggregate bytes", func(value *receipt) { value.TotalCompressedBytes++ }, "total_compressed_bytes"},
		{"unsafe repository", func(value *receipt) { value.Results[0].Repository = "owner/../repo" }, "owner/repository"},
		{"uppercase commit", func(value *receipt) { value.Results[0].Commit = strings.ToUpper(value.Results[0].Commit) }, "lowercase hexadecimal"},
		{"wrong commit URL", func(value *receipt) { value.Results[0].CommitURL += "/wrong" }, "commit_url"},
		{"equal outer hashes", func(value *receipt) { value.Results[0].TarGZSHA256 = value.Results[0].ZIPSHA256 }, "outer archive hashes"},
		{"portable mismatch", func(value *receipt) { value.Results[0].Match = false }, "match is false"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := testReceipt()
			test.mutate(&value)
			if err := validateReceipt(value); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateReceipt() error = %v, want substring %q", err, test.want)
			}
		})
	}
	withOptionalMetadata := testReceipt()
	withOptionalMetadata.ImplementationCommit = strings.Repeat("a", 40)
	withOptionalMetadata.ReverifiedAtUTC = "2026-08-30T13:00:00Z"
	if err := validateReceipt(withOptionalMetadata); err != nil {
		t.Fatalf("validateReceipt(optional metadata): %v", err)
	}
}

func TestCommittedReceiptValid(t *testing.T) {
	parsed, err := readReceipt(filepath.Join("..", "..", "CORPUS.json"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Pairs != 18 || len(parsed.Results) != 18 {
		t.Fatalf("committed receipt contains %d/%d pairs, want 18", parsed.Pairs, len(parsed.Results))
	}
}

func TestGitHubURLs(t *testing.T) {
	commit := strings.Repeat("a", 40)
	commitURL, zipURL, tarGZURL, err := githubURLs("BurntSushi/ripgrep", commit)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://github.com/BurntSushi/ripgrep/commit/" + commit; commitURL != want {
		t.Fatalf("commit URL = %q, want %q", commitURL, want)
	}
	if want := "https://github.com/BurntSushi/ripgrep/archive/" + commit + ".zip"; zipURL != want {
		t.Fatalf("ZIP URL = %q, want %q", zipURL, want)
	}
	if want := "https://github.com/BurntSushi/ripgrep/archive/" + commit + ".tar.gz"; tarGZURL != want {
		t.Fatalf("TAR.GZ URL = %q, want %q", tarGZURL, want)
	}
	if _, _, _, err := githubURLs("owner/repo/extra", commit); err == nil {
		t.Fatal("githubURLs accepted an invalid repository")
	}
}

func TestCacheFileIsStableAndContained(t *testing.T) {
	cache := t.TempDir()
	commit := strings.Repeat("b", 40)
	first := cacheFile(cache, "owner/repo", commit, "tar.gz")
	second := cacheFile(cache, "owner/repo", commit, "tar.gz")
	if first != second {
		t.Fatalf("cacheFile is not stable: %q != %q", first, second)
	}
	if filepath.Dir(first) != cache || !strings.HasSuffix(first, ".tar.gz") {
		t.Fatalf("unexpected cache path %q", first)
	}
	if first == cacheFile(cache, "other/repo", commit, "tar.gz") {
		t.Fatal("different repositories share a cache path")
	}
}

func TestCacheLookup(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "archive.zip")
	content := []byte("complete archive bytes")
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	wantDigest := hex.EncodeToString(digest[:])

	hit, err := cacheLookup(filename, int64(len(content)), wantDigest)
	if err != nil || !hit {
		t.Fatalf("cacheLookup(valid) = %v, %v", hit, err)
	}
	hit, err = cacheLookup(filename, int64(len(content))+1, wantDigest)
	if err != nil || hit {
		t.Fatalf("cacheLookup(wrong size) = %v, %v", hit, err)
	}
	hit, err = cacheLookup(filename, int64(len(content)), strings.Repeat("0", 64))
	if err != nil || hit {
		t.Fatalf("cacheLookup(wrong hash) = %v, %v", hit, err)
	}
	hit, err = cacheLookup(filepath.Join(directory, "missing"), 1, strings.Repeat("0", 64))
	if err != nil || hit {
		t.Fatalf("cacheLookup(missing) = %v, %v", hit, err)
	}

	nonRegular := filepath.Join(directory, "directory")
	if err := os.Mkdir(nonRegular, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := cacheLookup(nonRegular, 0, strings.Repeat("0", 64)); err == nil {
		t.Fatal("cacheLookup accepted a non-regular path")
	}
}

func TestWriteRerunReceiptIsAtomicAndDoesNotOverwrite(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "proof.json")
	value := rerunReceipt{
		Schema:          "samepack-corpus-proof-v1",
		GeneratedAtUTC:  "2026-08-30T12:00:00Z",
		SourceSchema:    receiptSchema,
		DeclaredPairs:   1,
		SelectedPairs:   1,
		PassedPairs:     1,
		AllSelectedPass: true,
		Results:         []observedResult{},
	}
	if err := writeRerunReceipt(filename, value); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var decoded rerunReceipt
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("written receipt is not JSON: %v", err)
	}
	if decoded.Schema != value.Schema || !decoded.AllSelectedPass {
		t.Fatalf("written receipt = %+v", decoded)
	}
	if err := writeRerunReceipt(filename, rerunReceipt{Schema: "replacement"}); err == nil {
		t.Fatal("writeRerunReceipt overwrote an existing receipt")
	}
	data, err = os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "replacement") {
		t.Fatal("existing receipt was modified")
	}
}

func testReceipt() receipt {
	commit := strings.Repeat("a", 40)
	zipDigest := strings.Repeat("1", 64)
	tarDigest := strings.Repeat("2", 64)
	payloadDigest := strings.Repeat("3", 64)
	portableDigest := strings.Repeat("4", 64)
	item := result{
		Repository:     "owner/repo",
		Commit:         commit,
		CommitURL:      "https://github.com/owner/repo/commit/" + commit,
		ZIPBytes:       10,
		ZIPSHA256:      zipDigest,
		TarGZBytes:     20,
		TarGZSHA256:    tarDigest,
		PayloadPaths:   2,
		PayloadBytes:   25,
		PayloadSHA256:  payloadDigest,
		PortableSHA256: portableDigest,
		Match:          true,
		ElapsedMS:      1,
	}
	return receipt{
		Schema:               receiptSchema,
		GeneratedAtUTC:       "2026-08-30T10:18:17Z",
		SamepackVersion:      "0.2.0",
		GoVersion:            "go version go1.26.5 windows/amd64",
		Pairs:                1,
		Archives:             2,
		TotalCompressedBytes: 30,
		AllOuterHashesDiffer: true,
		AllPortableMatches:   true,
		Results:              []result{item},
	}
}
