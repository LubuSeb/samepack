package archiveio

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

type ChangedPath struct {
	Path         string `json:"path"`
	BeforeKind   string `json:"before_kind"`
	AfterKind    string `json:"after_kind"`
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256"`
	BeforeSize   int64  `json:"before_size"`
	AfterSize    int64  `json:"after_size"`
}

type MetadataChange struct {
	Path   string   `json:"path"`
	Fields []string `json:"fields"`
}

type BehaviorChange struct {
	Path             string `json:"path"`
	BeforeExecutable bool   `json:"before_executable"`
	AfterExecutable  bool   `json:"after_executable"`
}

type Comparison struct {
	Classification     string           `json:"classification"`
	ByteIdentical      bool             `json:"byte_identical"`
	ContentIdentical   bool             `json:"content_identical"`
	PortableIdentical  bool             `json:"portable_identical"`
	Before             Snapshot         `json:"before"`
	After              Snapshot         `json:"after"`
	Reasons            []string         `json:"reasons"`
	Added              []string         `json:"added"`
	Removed            []string         `json:"removed"`
	Modified           []ChangedPath    `json:"modified"`
	Metadata           []MetadataChange `json:"metadata"`
	BehaviorModified   []BehaviorChange `json:"behavior_modified"`
	OrderChanged       bool             `json:"order_changed"`
	DirectoriesChanged bool             `json:"directory_entries_changed"`
	StrippedRoots      []string         `json:"stripped_roots"`
}

func Compare(before, after Snapshot) Comparison {
	byteIdentical := before.ByteSHA256 == after.ByteSHA256
	strippedRoots := []string{}
	beforeRoot, beforeWrapped := singleArchiveRoot(before.Entries)
	afterRoot, afterWrapped := singleArchiveRoot(after.Entries)
	if beforeWrapped && afterWrapped && beforeRoot != afterRoot {
		before = stripArchiveRoot(before, beforeRoot)
		after = stripArchiveRoot(after, afterRoot)
		strippedRoots = []string{beforeRoot, afterRoot}
	}
	result := Comparison{
		ByteIdentical:    byteIdentical,
		ContentIdentical: before.ContentSHA256 == after.ContentSHA256,
		Before:           before,
		After:            after,
		Added:            []string{},
		Removed:          []string{},
		Modified:         []ChangedPath{},
		Metadata:         []MetadataChange{},
		BehaviorModified: []BehaviorChange{},
		Reasons:          []string{},
		StrippedRoots:    strippedRoots,
	}

	left := indexEntries(before.Entries)
	right := indexEntries(after.Entries)
	paths := make([]string, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	for path := range left {
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for path := range right {
		if _, exists := seen[path]; !exists {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)

	for _, path := range paths {
		oldEntry, oldExists := left[path]
		newEntry, newExists := right[path]
		switch {
		case !oldExists:
			if newEntry.Kind == "directory" {
				result.DirectoriesChanged = true
			} else {
				result.Added = append(result.Added, path)
			}
		case !newExists:
			if oldEntry.Kind == "directory" {
				result.DirectoriesChanged = true
			} else {
				result.Removed = append(result.Removed, path)
			}
		default:
			if oldEntry.Kind != newEntry.Kind || oldEntry.Size != newEntry.Size || oldEntry.SHA256 != newEntry.SHA256 {
				result.Modified = append(result.Modified, ChangedPath{
					Path:         path,
					BeforeKind:   oldEntry.Kind,
					AfterKind:    newEntry.Kind,
					BeforeSHA256: oldEntry.SHA256,
					AfterSHA256:  newEntry.SHA256,
					BeforeSize:   oldEntry.Size,
					AfterSize:    newEntry.Size,
				})
			}
			oldExecutable := oldEntry.Mode&0o111 != 0
			newExecutable := newEntry.Mode&0o111 != 0
			if oldEntry.Kind == "file" && newEntry.Kind == "file" && oldExecutable != newExecutable {
				result.BehaviorModified = append(result.BehaviorModified, BehaviorChange{
					Path:             path,
					BeforeExecutable: oldExecutable,
					AfterExecutable:  newExecutable,
				})
			}
			fields := make([]string, 0, 2)
			if oldEntry.Mode != newEntry.Mode {
				fields = append(fields, "mode")
			}
			if oldEntry.ModTime != newEntry.ModTime {
				fields = append(fields, "timestamp")
			}
			if len(fields) > 0 {
				result.Metadata = append(result.Metadata, MetadataChange{Path: path, Fields: fields})
			}
		}
	}

	result.OrderChanged = !slices.Equal(before.Order, after.Order)
	if before.Format != after.Format {
		result.Reasons = append(result.Reasons, fmt.Sprintf("archive format changed (%s -> %s)", before.Format, after.Format))
	}
	if len(result.StrippedRoots) == 2 {
		result.Reasons = append(result.Reasons, fmt.Sprintf("top-level release directories ignored (%s -> %s)", result.StrippedRoots[0], result.StrippedRoots[1]))
	}
	if result.OrderChanged {
		result.Reasons = append(result.Reasons, "entry order changed")
	}
	if result.DirectoriesChanged {
		result.Reasons = append(result.Reasons, "explicit directory entries changed")
	}
	if hasMetadataField(result.Metadata, "timestamp") {
		result.Reasons = append(result.Reasons, "entry timestamps changed")
	}
	if hasMetadataField(result.Metadata, "mode") {
		result.Reasons = append(result.Reasons, "entry permissions changed")
	}
	if len(result.BehaviorModified) > 0 {
		result.Reasons = append(result.Reasons, "executable permissions changed")
	}
	result.PortableIdentical = result.ContentIdentical && len(result.BehaviorModified) == 0

	switch {
	case result.ByteIdentical:
		result.Classification = "byte_identical"
	case result.PortableIdentical:
		result.Classification = "metadata_only"
		if len(result.Reasons) == 0 {
			result.Reasons = append(result.Reasons, "container encoding differs")
		}
	case !result.ContentIdentical:
		result.Classification = "content_changed"
	default:
		result.Classification = "behavior_changed"
	}
	return result
}

func singleArchiveRoot(entries []Entry) (string, bool) {
	root := ""
	hasNestedPath := false
	for _, entry := range entries {
		separator := strings.IndexByte(entry.Path, '/')
		candidate := entry.Path
		if separator >= 0 {
			candidate = entry.Path[:separator]
			hasNestedPath = true
		} else if entry.Kind != "directory" {
			return "", false
		}
		if root == "" {
			root = candidate
		} else if root != candidate {
			return "", false
		}
	}
	return root, root != "" && hasNestedPath
}

func stripArchiveRoot(snapshot Snapshot, root string) Snapshot {
	prefix := root + "/"
	entries := make([]Entry, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if entry.Path == root && entry.Kind == "directory" {
			continue
		}
		entry.Path = strings.TrimPrefix(entry.Path, prefix)
		entries = append(entries, entry)
	}
	order := make([]string, 0, len(snapshot.Order))
	for _, name := range snapshot.Order {
		if name == root {
			continue
		}
		order = append(order, strings.TrimPrefix(name, prefix))
	}
	snapshot.Entries = entries
	snapshot.Order = order
	snapshot.ContentSHA256 = contentRoot(entries)
	return snapshot
}

func indexEntries(entries []Entry) map[string]Entry {
	result := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		result[entry.Path] = entry
	}
	return result
}

func hasMetadataField(changes []MetadataChange, field string) bool {
	for _, change := range changes {
		if slices.Contains(change.Fields, field) {
			return true
		}
	}
	return false
}
