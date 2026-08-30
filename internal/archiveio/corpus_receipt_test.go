package archiveio

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCommittedCorpusReceiptIsInternallyConsistent(t *testing.T) {
	type corpusResult struct {
		Repository     string `json:"repository"`
		Commit         string `json:"commit"`
		ZIPBytes       int64  `json:"zip_bytes"`
		ZIPSHA256      string `json:"zip_sha256"`
		TarGZBytes     int64  `json:"tar_gz_bytes"`
		TarGZSHA256    string `json:"tar_gz_sha256"`
		PayloadPaths   int    `json:"payload_paths"`
		PayloadBytes   int64  `json:"payload_bytes"`
		PayloadSHA256  string `json:"payload_sha256"`
		PortableSHA256 string `json:"portable_sha256"`
		Match          bool   `json:"match"`
	}
	type corpusReceipt struct {
		Schema               string         `json:"schema"`
		Pairs                int            `json:"pairs"`
		Archives             int            `json:"archives"`
		TotalCompressedBytes int64          `json:"total_compressed_bytes"`
		AllOuterHashesDiffer bool           `json:"all_outer_hashes_differ"`
		AllPortableMatches   bool           `json:"all_portable_matches"`
		Results              []corpusResult `json:"results"`
	}

	data, err := os.ReadFile("../../CORPUS.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt corpusReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != "samepack-corpus-v1" || receipt.Pairs != len(receipt.Results) || receipt.Archives != receipt.Pairs*2 {
		t.Fatalf("invalid corpus summary: %#v", receipt)
	}
	if !receipt.AllOuterHashesDiffer || !receipt.AllPortableMatches || receipt.Pairs < 18 {
		t.Fatalf("corpus proof was weakened: %#v", receipt)
	}
	seen := make(map[string]struct{}, len(receipt.Results))
	var compressedTotal int64
	for _, result := range receipt.Results {
		key := result.Repository + "@" + result.Commit
		if result.Repository == "" || len(result.Commit) != 40 {
			t.Fatalf("invalid corpus identity %q", key)
		}
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate corpus identity %q", key)
		}
		seen[key] = struct{}{}
		if !result.Match || result.ZIPSHA256 == result.TarGZSHA256 || result.ZIPBytes <= 0 || result.TarGZBytes <= 0 || result.PayloadPaths <= 0 || result.PayloadBytes <= 0 {
			t.Fatalf("invalid result for %s: %#v", key, result)
		}
		for _, digest := range []string{result.ZIPSHA256, result.TarGZSHA256, result.PayloadSHA256, result.PortableSHA256} {
			if err := validateDigest(digest); err != nil {
				t.Fatalf("invalid digest for %s: %v", key, err)
			}
		}
		compressedTotal += result.ZIPBytes + result.TarGZBytes
	}
	if compressedTotal != receipt.TotalCompressedBytes {
		t.Fatalf("compressed-byte total mismatch: %d != %d", compressedTotal, receipt.TotalCompressedBytes)
	}
}
