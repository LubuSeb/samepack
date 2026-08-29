package archiveio

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
)

const (
	maxEntries   = 100_000
	maxEntrySize = int64(1 << 30) // 1 GiB
	maxTotalSize = int64(4 << 30) // 4 GiB
)

// Entry is the content and portable metadata Samepack observes for one path.
type Entry struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Mode    uint32 `json:"mode"`
	ModTime string `json:"mod_time"`
}

// Snapshot is a safe, extraction-free view of an archive.
type Snapshot struct {
	Archive       string   `json:"archive"`
	Format        string   `json:"format"`
	ByteSHA256    string   `json:"byte_sha256"`
	ContentSHA256 string   `json:"content_sha256"`
	Entries       []Entry  `json:"entries"`
	Order         []string `json:"order"`
}

func contentRoot(entries []Entry) string {
	ordered := append([]Entry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })

	h := sha256.New()
	for _, entry := range ordered {
		if entry.Kind == "directory" {
			continue
		}
		writeFrame(h, []byte(entry.Path))
		writeFrame(h, []byte(entry.Kind))
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(entry.Size))
		writeFrame(h, size[:])
		digest, err := hex.DecodeString(entry.SHA256)
		if err != nil {
			panic(fmt.Sprintf("internal invalid digest for %s: %v", entry.Path, err))
		}
		writeFrame(h, digest)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeFrame(w io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(value)
}
