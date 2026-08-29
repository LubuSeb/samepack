package archiveio

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

var errUnsupportedArchive = errors.New("unsupported archive: expected tar, tar.gz, tgz, or zip")

// Inspect reads archive metadata and hashes content without extracting anything.
func Inspect(filename string) (Snapshot, error) {
	rawDigest, err := hashFile(filename)
	if err != nil {
		return Snapshot{}, err
	}

	format, err := detectFormat(filename)
	if err != nil {
		return Snapshot{}, err
	}

	var entries []Entry
	var order []string
	switch format {
	case "zip":
		entries, order, err = readZIP(filename)
	case "tar", "tar.gz":
		entries, order, err = readTAR(filename, format == "tar.gz")
	default:
		err = errUnsupportedArchive
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect %s: %w", filename, err)
	}

	return Snapshot{
		Archive:       filename,
		Format:        format,
		ByteSHA256:    rawDigest,
		ContentSHA256: contentRoot(entries),
		Entries:       entries,
		Order:         order,
	}, nil
}

func detectFormat(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	var magic [4]byte
	n, err := io.ReadFull(f, magic[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", fmt.Errorf("read header: %w", err)
	}
	if n >= 4 && string(magic[:2]) == "PK" && (string(magic[2:]) == "\x03\x04" || string(magic[2:]) == "\x05\x06" || string(magic[2:]) == "\x07\x08") {
		return "zip", nil
	}
	if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		return "tar.gz", nil
	}
	if n > 0 {
		return "tar", nil
	}
	return "", errUnsupportedArchive
}

func readTAR(filename string, compressed bool) ([]Entry, []string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var source io.Reader = f
	var gz *gzip.Reader
	if compressed {
		gz, err = gzip.NewReader(f)
		if err != nil {
			return nil, nil, fmt.Errorf("gzip header: %w", err)
		}
		defer gz.Close()
		source = gz
	}

	reader := tar.NewReader(source)
	seen := make(map[string]struct{})
	caseFolded := make(map[string]string)
	entries := make([]Entry, 0)
	order := make([]string, 0)
	var total int64

	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nil, fmt.Errorf("tar stream: %w", nextErr)
		}
		if len(entries) >= maxEntries {
			return nil, nil, fmt.Errorf("archive exceeds %d entries", maxEntries)
		}
		if isTARMetadata(header.Typeflag) {
			continue
		}

		name, err := safeArchivePath(header.Name)
		if err != nil {
			return nil, nil, err
		}
		if err := registerPath(name, seen, caseFolded); err != nil {
			return nil, nil, err
		}

		kind := ""
		var digest string
		var size int64
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			kind = "file"
			size = header.Size
			if err := checkSize(size, &total); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			digest, err = hashExactly(reader, size)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
		case tar.TypeDir:
			kind = "directory"
			digest = emptyDigest()
		case tar.TypeSymlink:
			kind = "symlink"
			size = int64(len(header.Linkname))
			digest = hashBytes([]byte(header.Linkname))
		default:
			return nil, nil, fmt.Errorf("%s: unsupported tar entry type %d", name, header.Typeflag)
		}

		entries = append(entries, Entry{
			Path:    name,
			Kind:    kind,
			Size:    size,
			SHA256:  digest,
			Mode:    uint32(header.Mode) & 0o777,
			ModTime: normalizeTime(header.ModTime),
		})
		order = append(order, name)
	}
	return entries, order, nil
}

func isTARMetadata(typeFlag byte) bool {
	return typeFlag == tar.TypeXHeader ||
		typeFlag == tar.TypeXGlobalHeader ||
		typeFlag == tar.TypeGNULongName ||
		typeFlag == tar.TypeGNULongLink
}

func readZIP(filename string) ([]Entry, []string, error) {
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("zip directory: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > maxEntries {
		return nil, nil, fmt.Errorf("archive exceeds %d entries", maxEntries)
	}

	seen := make(map[string]struct{})
	caseFolded := make(map[string]string)
	entries := make([]Entry, 0, len(reader.File))
	order := make([]string, 0, len(reader.File))
	var total int64
	for _, file := range reader.File {
		name, err := safeArchivePath(file.Name)
		if err != nil {
			return nil, nil, err
		}
		if err := registerPath(name, seen, caseFolded); err != nil {
			return nil, nil, err
		}

		mode := file.Mode()
		kind := "file"
		var digest string
		var size int64
		switch {
		case mode.IsDir() || strings.HasSuffix(file.Name, "/"):
			kind = "directory"
			digest = emptyDigest()
		case mode&os.ModeSymlink != 0:
			kind = "symlink"
			if file.UncompressedSize64 > uint64(maxEntrySize) {
				return nil, nil, fmt.Errorf("%s: entry exceeds %d bytes", name, maxEntrySize)
			}
			digest, size, err = hashZIPEntry(file)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
		default:
			if file.UncompressedSize64 > uint64(maxEntrySize) {
				return nil, nil, fmt.Errorf("%s: entry exceeds %d bytes", name, maxEntrySize)
			}
			size = int64(file.UncompressedSize64)
			if err := checkSize(size, &total); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			var actual int64
			digest, actual, err = hashZIPEntry(file)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			if actual != size {
				return nil, nil, fmt.Errorf("%s: declared size %d, read %d", name, size, actual)
			}
		}

		entries = append(entries, Entry{
			Path:    name,
			Kind:    kind,
			Size:    size,
			SHA256:  digest,
			Mode:    uint32(mode.Perm()),
			ModTime: normalizeTime(file.Modified),
		})
		order = append(order, name)
	}
	return entries, order, nil
}

func hashZIPEntry(file *zip.File) (string, int64, error) {
	r, err := file.Open()
	if err != nil {
		return "", 0, err
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxEntrySize+1))
	if err != nil {
		return "", n, err
	}
	if n > maxEntrySize {
		return "", n, fmt.Errorf("entry exceeds %d bytes", maxEntrySize)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func safeArchivePath(name string) (string, error) {
	if name == "" {
		return "", errors.New("archive contains an empty path")
	}
	if strings.Contains(name, "\\") || hasControlCharacter(name) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	cleaned := path.Clean(trimmed)
	if cleaned == "." || cleaned == ".." || path.IsAbs(cleaned) || strings.HasPrefix(cleaned, "../") || hasWindowsVolume(cleaned) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return cleaned, nil
}

func hasControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func hasWindowsVolume(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':'
}

func registerPath(name string, seen map[string]struct{}, caseFolded map[string]string) error {
	if _, exists := seen[name]; exists {
		return fmt.Errorf("duplicate archive path %q", name)
	}
	folded := strings.ToLower(name)
	if previous, exists := caseFolded[folded]; exists && previous != name {
		return fmt.Errorf("case-colliding archive paths %q and %q", previous, name)
	}
	seen[name] = struct{}{}
	caseFolded[folded] = name
	return nil
}

func checkSize(size int64, total *int64) error {
	if size < 0 {
		return errors.New("negative entry size")
	}
	if size > maxEntrySize {
		return fmt.Errorf("entry exceeds %d bytes", maxEntrySize)
	}
	if *total > maxTotalSize-size {
		return fmt.Errorf("archive exceeds %d total bytes", maxTotalSize)
	}
	*total += size
	return nil
}

func hashExactly(r io.Reader, size int64) (string, error) {
	h := sha256.New()
	n, err := io.CopyN(h, r, size)
	if err != nil {
		return "", fmt.Errorf("declared size %d, read %d: %w", size, n, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func emptyDigest() string { return hashBytes(nil) }

func normalizeTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
