package archiveio

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type sourceEntry struct {
	localPath string
	name      string
	info      os.FileInfo
}

type PackOptions struct {
	Format             string
	PreserveExecutable bool
}

// Pack creates a canonical archive from a directory and returns its inspected snapshot.
func Pack(sourceDir, output, format string) (Snapshot, error) {
	return PackWithOptions(sourceDir, output, PackOptions{Format: format})
}

// PackWithOptions creates a canonical archive with an explicit mode policy.
func PackWithOptions(sourceDir, output string, options PackOptions) (Snapshot, error) {
	format, err := normalizeFormat(options.Format, output)
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateOutputPath(sourceDir, output); err != nil {
		return Snapshot{}, err
	}
	entries, err := collectSource(sourceDir)
	if err != nil {
		return Snapshot{}, err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return Snapshot{}, fmt.Errorf("create output directory: %w", err)
	}

	temp, err := os.CreateTemp(filepath.Dir(output), ".samepack-*")
	if err != nil {
		return Snapshot{}, fmt.Errorf("create temporary output: %w", err)
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(0o644); err != nil {
		return Snapshot{}, fmt.Errorf("set output permissions: %w", err)
	}

	switch format {
	case "tar":
		err = writeTAR(temp, entries, options.PreserveExecutable)
	case "tar.gz":
		err = writeTGZ(temp, entries, options.PreserveExecutable)
	case "zip":
		err = writeZIP(temp, entries, options.PreserveExecutable)
	}
	if err != nil {
		return Snapshot{}, err
	}
	if err := temp.Sync(); err != nil {
		return Snapshot{}, fmt.Errorf("sync output: %w", err)
	}
	if err := temp.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close output: %w", err)
	}
	snapshot, err := Inspect(tempName)
	if err != nil {
		return Snapshot{}, fmt.Errorf("self-validate packed archive: %w", err)
	}
	if err := publishFile(tempName, output); err != nil {
		return Snapshot{}, err
	}
	snapshot.Archive = output
	return snapshot, nil
}

func collectSource(root string) ([]sourceEntry, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve source: %w", err)
	}
	rootInfo, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("source is not a directory: %s", root)
	}

	entries := make([]sourceEntry, 0)
	caseFolded := make(map[string]string)
	graphEntries := make([]Entry, 0)
	var total int64
	var pathTotal int64
	err = filepath.WalkDir(absolute, func(localPath string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if localPath == absolute {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symbolic links are rejected for portable deterministic output", localPath)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("%s: unsupported source type %s", localPath, info.Mode().Type())
		}
		relative, err := filepath.Rel(absolute, localPath)
		if err != nil {
			return err
		}
		name, err := safeArchivePath(filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		folded := strings.ToLower(name)
		if previous, exists := caseFolded[folded]; exists && previous != name {
			return fmt.Errorf("source contains case-colliding paths %q and %q", previous, name)
		}
		if err := addPathSize(name, &pathTotal); err != nil {
			return err
		}
		kind := "directory"
		if info.Mode().IsRegular() {
			kind = "file"
			if err := checkSize(info.Size(), &total); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		caseFolded[folded] = name
		entries = append(entries, sourceEntry{localPath: localPath, name: name, info: info})
		graphEntries = append(graphEntries, Entry{Path: name, Kind: kind})
		if len(entries) > maxEntries {
			return fmt.Errorf("source exceeds %d entries", maxEntries)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk source: %w", err)
	}
	if err := validatePathGraph(graphEntries); err != nil {
		return nil, fmt.Errorf("walk source: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, nil
}

func writeTGZ(output io.Writer, entries []sourceEntry, preserveExecutable bool) error {
	gz, err := gzip.NewWriterLevel(output, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	gz.Name = ""
	gz.Comment = ""
	gz.ModTime = time.Unix(0, 0).UTC()
	gz.OS = 255
	if err := writeTAR(gz, entries, preserveExecutable); err != nil {
		_ = gz.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip stream: %w", err)
	}
	return nil
}

func writeTAR(output io.Writer, entries []sourceEntry, preserveExecutable bool) error {
	w := tar.NewWriter(output)
	for _, entry := range entries {
		name := entry.name
		mode := canonicalFileMode(entry.info, preserveExecutable)
		size := entry.info.Size()
		typeFlag := byte(tar.TypeReg)
		if entry.info.IsDir() {
			name += "/"
			mode = 0o755
			size = 0
			typeFlag = tar.TypeDir
		}
		header := &tar.Header{
			Name:       name,
			Mode:       mode,
			Size:       size,
			ModTime:    time.Unix(0, 0).UTC(),
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Typeflag:   typeFlag,
			Uid:        0,
			Gid:        0,
			Uname:      "",
			Gname:      "",
			Format:     tar.FormatPAX,
		}
		if err := w.WriteHeader(header); err != nil {
			_ = w.Close()
			return fmt.Errorf("write tar header %s: %w", entry.name, err)
		}
		if !entry.info.Mode().IsRegular() {
			continue
		}
		if err := writeSourceFile(w, entry, preserveExecutable); err != nil {
			_ = w.Close()
			return err
		}
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close tar stream: %w", err)
	}
	return nil
}

func writeZIP(output io.Writer, entries []sourceEntry, preserveExecutable bool) error {
	w := zip.NewWriter(output)
	for _, entry := range entries {
		name := entry.name
		if entry.info.IsDir() {
			name += "/"
		}
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		if entry.info.IsDir() {
			header.Method = zip.Store
			header.SetMode(os.ModeDir | 0o755)
		} else {
			header.SetMode(os.FileMode(canonicalFileMode(entry.info, preserveExecutable)))
		}
		writer, err := w.CreateHeader(header)
		if err != nil {
			_ = w.Close()
			return fmt.Errorf("write zip header %s: %w", entry.name, err)
		}
		if entry.info.Mode().IsRegular() {
			if err := writeSourceFile(writer, entry, preserveExecutable); err != nil {
				_ = w.Close()
				return err
			}
		}
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close zip stream: %w", err)
	}
	return nil
}

func canonicalFileMode(info os.FileInfo, preserveExecutable bool) int64 {
	if preserveExecutable && info.Mode().Perm()&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

func writeSourceFile(output io.Writer, entry sourceEntry, preserveExecutable bool) error {
	f, err := os.Open(entry.localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", entry.name, err)
	}
	n, copyErr := io.Copy(output, io.LimitReader(f, entry.info.Size()+1))
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("read %s: %w", entry.name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", entry.name, closeErr)
	}
	if n != entry.info.Size() {
		return fmt.Errorf("%s changed while packing: expected %d bytes, read %d", entry.name, entry.info.Size(), n)
	}
	current, err := os.Stat(entry.localPath)
	if err != nil {
		return fmt.Errorf("restat %s: %w", entry.name, err)
	}
	if current.Size() != entry.info.Size() || !current.ModTime().Equal(entry.info.ModTime()) || canonicalFileMode(current, preserveExecutable) != canonicalFileMode(entry.info, preserveExecutable) {
		return fmt.Errorf("%s changed while packing", entry.name)
	}
	return nil
}

func normalizeFormat(format, output string) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		lower := strings.ToLower(output)
		switch {
		case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
			format = "tar.gz"
		case strings.HasSuffix(lower, ".tar"):
			format = "tar"
		case strings.HasSuffix(lower, ".zip"):
			format = "zip"
		default:
			format = "tar.gz"
		}
	}
	if format == "tgz" {
		format = "tar.gz"
	}
	if format != "tar" && format != "tar.gz" && format != "zip" {
		return "", fmt.Errorf("unsupported output format %q", format)
	}
	return format, nil
}

func publishFile(source, destination string) error {
	if err := os.Link(source, destination); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	return nil
}

func validateOutputPath(sourceDir, output string) error {
	sourceAbsolute, err := filepath.Abs(sourceDir)
	if err != nil {
		return fmt.Errorf("resolve source: %w", err)
	}
	outputAbsolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}
	if strings.EqualFold(filepath.VolumeName(sourceAbsolute), filepath.VolumeName(outputAbsolute)) {
		relative, err := filepath.Rel(sourceAbsolute, outputAbsolute)
		if err != nil {
			return fmt.Errorf("compare source and output paths: %w", err)
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return errors.New("output must be outside the source directory")
		}
	}
	if _, err := os.Stat(outputAbsolute); err == nil {
		return fmt.Errorf("output already exists: %s", output)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat output: %w", err)
	}
	return nil
}
