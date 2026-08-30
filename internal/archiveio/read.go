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
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var errUnsupportedArchive = errors.New("unsupported archive: expected tar, tar.gz, tgz, or zip")

// Inspect reads archive metadata and hashes content without extracting anything.
func Inspect(filename string) (Snapshot, error) {
	return inspectWithLimits(filename, defaultArchiveLimits)
}

func inspectWithLimits(filename string, limits archiveLimits) (Snapshot, error) {
	if limits.entries <= 0 || limits.entrySize <= 0 || limits.totalSize <= 0 || limits.totalSize < limits.entrySize {
		return Snapshot{}, errors.New("invalid archive limits")
	}
	f, err := os.Open(filename)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return Snapshot{}, fmt.Errorf("stat: %w", err)
	}
	if !before.Mode().IsRegular() {
		return Snapshot{}, errors.New("archive is not a regular file")
	}
	rawLimit, err := expandedTARLimit(limits)
	if err != nil {
		return Snapshot{}, err
	}
	if before.Size() > rawLimit {
		return Snapshot{}, fmt.Errorf("archive file exceeds %d bytes", rawLimit)
	}

	format, err := detectFormat(f)
	if err != nil {
		return Snapshot{}, err
	}

	var entries []Entry
	var order []string
	switch format {
	case "zip":
		reader, zipErr := zip.NewReader(f, before.Size())
		if zipErr != nil {
			err = fmt.Errorf("zip directory: %w", zipErr)
		} else {
			entries, order, err = readZIP(reader, limits)
		}
	case "tar", "tar.gz":
		if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
			err = fmt.Errorf("seek: %w", seekErr)
		} else {
			entries, order, err = readTAR(f, format == "tar.gz", limits)
		}
	default:
		err = errUnsupportedArchive
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect %s: %w", filename, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Snapshot{}, fmt.Errorf("seek for hash: %w", err)
	}
	rawDigest, err := hashReader(f)
	if err != nil {
		return Snapshot{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return Snapshot{}, fmt.Errorf("restat: %w", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return Snapshot{}, errors.New("archive changed while it was being inspected")
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

func detectFormat(source io.ReaderAt) (string, error) {
	var magic [4]byte
	n, err := source.ReadAt(magic[:], 0)
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

func readTAR(input io.Reader, compressed bool, limits archiveLimits) ([]Entry, []string, error) {
	var source io.Reader = input
	var gz *gzip.Reader
	var err error
	if compressed {
		gz, err = gzip.NewReader(input)
		if err != nil {
			return nil, nil, fmt.Errorf("gzip header: %w", err)
		}
		defer gz.Close()
		source = gz
	}

	expandedLimit, err := expandedTARLimit(limits)
	if err != nil {
		return nil, nil, err
	}
	bounded := &io.LimitedReader{R: source, N: expandedLimit + 1}
	reader := tar.NewReader(bounded)
	seen := make(map[string]struct{})
	caseFolded := make(map[string]string)
	entries := make([]Entry, 0)
	order := make([]string, 0)
	var total int64
	var pathTotal int64
	records := 0

	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nil, fmt.Errorf("tar stream: %w", nextErr)
		}
		records++
		if records > limits.entries {
			return nil, nil, fmt.Errorf("archive exceeds %d entries", limits.entries)
		}
		if isTARMetadata(header.Typeflag) {
			continue
		}

		name, err := safeArchivePath(header.Name)
		if err != nil {
			return nil, nil, err
		}
		if header.Mode&0o7000 != 0 {
			return nil, nil, fmt.Errorf("%s: privileged mode bits are unsupported", name)
		}
		if err := addPathSize(name, &pathTotal); err != nil {
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
			if err := checkSizeWithLimits(size, &total, limits); err != nil {
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
			if err := checkSizeWithLimits(size, &total, limits); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
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
	// tar.Reader stops at the logical end markers. Drain the bounded source so
	// GZIP validates its checksum/footer and compressed trailing bombs cannot be
	// accepted as a tiny archive without being charged to the expanded budget.
	if _, err := io.Copy(io.Discard, bounded); err != nil {
		return nil, nil, fmt.Errorf("tar trailer: %w", err)
	}
	if bounded.N == 0 {
		return nil, nil, fmt.Errorf("expanded tar stream exceeds %d bytes", expandedLimit)
	}
	if err := validatePathGraph(entries); err != nil {
		return nil, nil, err
	}
	return entries, order, nil
}

func expandedTARLimit(limits archiveLimits) (int64, error) {
	const perRecordOverhead = int64(maxPathBytes + 2048)
	const trailerAllowance = int64(2048)
	records := int64(limits.entries)
	if records > (int64(^uint64(0)>>1)-limits.totalSize-trailerAllowance-1)/perRecordOverhead {
		return 0, errors.New("archive limits overflow expanded tar budget")
	}
	return limits.totalSize + records*perRecordOverhead + trailerAllowance, nil
}

func isTARMetadata(typeFlag byte) bool {
	return typeFlag == tar.TypeXHeader ||
		typeFlag == tar.TypeXGlobalHeader ||
		typeFlag == tar.TypeGNULongName ||
		typeFlag == tar.TypeGNULongLink
}

func readZIP(reader *zip.Reader, limits archiveLimits) ([]Entry, []string, error) {
	if len(reader.File) > limits.entries {
		return nil, nil, fmt.Errorf("archive exceeds %d entries", limits.entries)
	}

	seen := make(map[string]struct{})
	caseFolded := make(map[string]string)
	entries := make([]Entry, 0, len(reader.File))
	order := make([]string, 0, len(reader.File))
	var total int64
	var pathTotal int64
	for _, file := range reader.File {
		name, err := safeArchivePath(file.Name)
		if err != nil {
			return nil, nil, err
		}
		if err := registerPath(name, seen, caseFolded); err != nil {
			return nil, nil, err
		}
		if err := addPathSize(name, &pathTotal); err != nil {
			return nil, nil, err
		}

		mode := file.Mode()
		if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return nil, nil, fmt.Errorf("%s: privileged mode bits are unsupported", name)
		}
		kind := "file"
		var digest string
		var size int64
		switch {
		case mode.IsDir() || strings.HasSuffix(file.Name, "/"):
			kind = "directory"
			digest = emptyDigest()
		case mode&os.ModeSymlink != 0:
			kind = "symlink"
			if file.UncompressedSize64 > uint64(limits.entrySize) {
				return nil, nil, fmt.Errorf("%s: entry exceeds %d bytes", name, limits.entrySize)
			}
			size = int64(file.UncompressedSize64)
			if err := checkSizeWithLimits(size, &total, limits); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			var actual int64
			digest, actual, err = hashZIPEntry(file, limits.entrySize)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			if actual != size {
				return nil, nil, fmt.Errorf("%s: declared size %d, read %d", name, size, actual)
			}
		case mode.IsRegular():
			if file.UncompressedSize64 > uint64(limits.entrySize) {
				return nil, nil, fmt.Errorf("%s: entry exceeds %d bytes", name, limits.entrySize)
			}
			size = int64(file.UncompressedSize64)
			if err := checkSizeWithLimits(size, &total, limits); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			var actual int64
			digest, actual, err = hashZIPEntry(file, limits.entrySize)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			if actual != size {
				return nil, nil, fmt.Errorf("%s: declared size %d, read %d", name, size, actual)
			}
		default:
			return nil, nil, fmt.Errorf("%s: unsupported zip entry type %s", name, mode.Type())
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
	if err := validatePathGraph(entries); err != nil {
		return nil, nil, err
	}
	return entries, order, nil
}

func hashZIPEntry(file *zip.File, entryLimit int64) (string, int64, error) {
	r, err := file.Open()
	if err != nil {
		return "", 0, err
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, entryLimit+1))
	if err != nil {
		return "", n, err
	}
	if n > entryLimit {
		return "", n, fmt.Errorf("entry exceeds %d bytes", entryLimit)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func safeArchivePath(name string) (string, error) {
	if name == "" {
		return "", errors.New("archive contains an empty path")
	}
	if !utf8.ValidString(name) {
		return "", errors.New("archive contains a path that is not valid UTF-8")
	}
	if len(name) > maxPathBytes {
		return "", fmt.Errorf("archive path exceeds %d bytes", maxPathBytes)
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

func addPathSize(name string, total *int64) error {
	size := int64(len(name))
	if *total > maxPathTotal-size {
		return fmt.Errorf("archive paths exceed %d total bytes", maxPathTotal)
	}
	*total += size
	return nil
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

func validatePathGraph(entries []Entry) error {
	type graphPath struct {
		original string
		folded   string
		kind     string
	}
	records := make([]graphPath, len(entries))
	for index, entry := range entries {
		// NUL sorts before every accepted path character, so a directory's whole
		// subtree is contiguous and immediately follows the directory itself.
		records[index] = graphPath{
			original: entry.Path,
			folded:   strings.ReplaceAll(strings.ToLower(entry.Path), "/", "\x00"),
			kind:     entry.Kind,
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].folded == records[j].folded {
			return records[i].original < records[j].original
		}
		return records[i].folded < records[j].folded
	})
	for index := 1; index < len(records); index++ {
		previous := records[index-1]
		current := records[index]
		if caseVariedComponent(previous.original, previous.folded, current.original, current.folded) {
			return fmt.Errorf("case-colliding archive path components in %q and %q", previous.original, current.original)
		}
		if previous.kind != "directory" && len(current.folded) > len(previous.folded) &&
			strings.HasPrefix(current.folded, previous.folded) && current.folded[len(previous.folded)] == 0 {
			return fmt.Errorf("archive path %q is nested below %s %q", current.original, previous.kind, previous.original)
		}
	}
	return nil
}

func caseVariedComponent(left, foldedLeft, right, foldedRight string) bool {
	leftStart, foldedLeftStart := 0, 0
	rightStart, foldedRightStart := 0, 0
	for leftStart < len(left) && rightStart < len(right) {
		leftEnd := componentEnd(left, leftStart, '/')
		rightEnd := componentEnd(right, rightStart, '/')
		foldedLeftEnd := componentEnd(foldedLeft, foldedLeftStart, 0)
		foldedRightEnd := componentEnd(foldedRight, foldedRightStart, 0)
		if foldedLeft[foldedLeftStart:foldedLeftEnd] != foldedRight[foldedRightStart:foldedRightEnd] {
			return false
		}
		if left[leftStart:leftEnd] != right[rightStart:rightEnd] {
			return true
		}
		leftStart, foldedLeftStart = leftEnd+1, foldedLeftEnd+1
		rightStart, foldedRightStart = rightEnd+1, foldedRightEnd+1
	}
	return false
}

func componentEnd(value string, start int, separator byte) int {
	if offset := strings.IndexByte(value[start:], separator); offset >= 0 {
		return start + offset
	}
	return len(value)
}

func checkSize(size int64, total *int64) error {
	return checkSizeWithLimits(size, total, defaultArchiveLimits)
}

func checkSizeWithLimits(size int64, total *int64, limits archiveLimits) error {
	if size < 0 {
		return errors.New("negative entry size")
	}
	if size > limits.entrySize {
		return fmt.Errorf("entry exceeds %d bytes", limits.entrySize)
	}
	if *total > limits.totalSize-size {
		return fmt.Errorf("archive exceeds %d total bytes", limits.totalSize)
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

func hashReader(source io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, source); err != nil {
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
