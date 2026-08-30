package archiveio

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	ManifestFormat           = "samepack-manifest"
	ManifestVersion          = 1
	ManifestAlgorithm        = "samepack-portable-v1"
	WrapperNone              = "none"
	WrapperStripSingle       = "strip-single-directory"
	maxManifestBytes   int64 = 64 << 20
)

// Manifest is a deterministic, reviewable record of an archive payload.
// RootSHA256 additionally commits to executable-file semantics, while
// PayloadSHA256 intentionally ignores archive metadata and permissions.
type Manifest struct {
	Format        string                `json:"format"`
	Version       int                   `json:"version"`
	Algorithm     string                `json:"algorithm"`
	RootSHA256    string                `json:"root_sha256"`
	PayloadSHA256 string                `json:"payload_sha256"`
	Normalization ManifestNormalization `json:"normalization"`
	Source        ManifestSource        `json:"source"`
	Entries       []ManifestEntry       `json:"entries"`
}

type ManifestNormalization struct {
	Wrapper string `json:"wrapper"`
}

type ManifestSource struct {
	Format         string `json:"format"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	StrippedRoot   string `json:"stripped_root,omitempty"`
}

type ManifestEntry struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}

type VerifiedPath struct {
	Path           string `json:"path"`
	ExpectedKind   string `json:"expected_kind"`
	ObservedKind   string `json:"observed_kind"`
	ExpectedSize   int64  `json:"expected_size"`
	ObservedSize   int64  `json:"observed_size"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ObservedSHA256 string `json:"observed_sha256"`
}

type ExecutableChange struct {
	Path               string `json:"path"`
	ExpectedExecutable bool   `json:"expected_executable"`
	ObservedExecutable bool   `json:"observed_executable"`
}

// Verification is the complete, untruncated result for one archive.
type Verification struct {
	Classification      string             `json:"classification"`
	Match               bool               `json:"match"`
	PayloadIdentical    bool               `json:"payload_identical"`
	PortableIdentical   bool               `json:"portable_identical"`
	Archive             string             `json:"archive"`
	Format              string             `json:"format"`
	ArtifactSHA256      string             `json:"artifact_sha256"`
	RecordedArtifactSHA string             `json:"recorded_artifact_sha256"`
	ExpectedRootSHA256  string             `json:"expected_root_sha256"`
	ObservedRootSHA256  string             `json:"observed_root_sha256"`
	ExpectedPayloadSHA  string             `json:"expected_payload_sha256"`
	ObservedPayloadSHA  string             `json:"observed_payload_sha256"`
	WrapperPolicy       string             `json:"wrapper_policy"`
	StrippedRoot        string             `json:"stripped_root,omitempty"`
	PayloadPaths        int                `json:"payload_paths"`
	PayloadBytes        int64              `json:"payload_bytes"`
	Added               []string           `json:"added"`
	Removed             []string           `json:"removed"`
	Modified            []VerifiedPath     `json:"modified"`
	ExecutableChanged   []ExecutableChange `json:"executable_changed"`
}

// CreateManifest records one inspected archive using an explicit wrapper policy.
func CreateManifest(snapshot Snapshot, wrapperPolicy string) (Manifest, error) {
	normalized, strippedRoot, err := normalizeManifestSnapshot(snapshot, wrapperPolicy)
	if err != nil {
		return Manifest{}, err
	}
	entries := manifestEntries(normalized.Entries)
	root, err := portableRoot(entries, wrapperPolicy)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		Format:        ManifestFormat,
		Version:       ManifestVersion,
		Algorithm:     ManifestAlgorithm,
		RootSHA256:    root,
		PayloadSHA256: contentRoot(normalized.Entries),
		Normalization: ManifestNormalization{Wrapper: wrapperPolicy},
		Source: ManifestSource{
			Format:         snapshot.Format,
			ArtifactSHA256: snapshot.ByteSHA256,
			StrippedRoot:   strippedRoot,
		},
		Entries: entries,
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, fmt.Errorf("create manifest: %w", err)
	}
	return manifest, nil
}

// EncodeManifest writes deterministic, indented JSON with no timestamps or local paths.
func EncodeManifest(w io.Writer, manifest Manifest) error {
	encoded, err := encodeManifestBytes(manifest, maxManifestBytes)
	if err != nil {
		return err
	}
	n, err := w.Write(encoded)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	if n != len(encoded) {
		return fmt.Errorf("encode manifest: %w", io.ErrShortWrite)
	}
	return nil
}

func encodeManifestBytes(manifest Manifest, limit int64) ([]byte, error) {
	if err := ValidateManifest(manifest); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(manifest); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if int64(encoded.Len()) > limit {
		return nil, fmt.Errorf("encoded manifest exceeds %d bytes", limit)
	}
	return encoded.Bytes(), nil
}

// DecodeManifest reads exactly one strictly validated manifest document.
func DecodeManifest(r io.Reader) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if int64(len(data)) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest exceeds %d bytes", maxManifestBytes)
	}
	if !utf8.Valid(data) {
		return Manifest{}, errors.New("decode manifest: input is not valid UTF-8")
	}
	if err := validateJSONUnicodeEscapes(data); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := validateManifestJSONShape(data); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, errors.New("decode manifest: trailing JSON value")
		}
		return Manifest{}, fmt.Errorf("decode manifest: trailing data: %w", err)
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, fmt.Errorf("validate manifest: %w", err)
	}
	return manifest, nil
}

func validateJSONUnicodeEscapes(data []byte) error {
	inString := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			if index+1 >= len(data) {
				return errors.New("incomplete JSON escape")
			}
			if data[index+1] != 'u' {
				index++
				continue
			}
			unit, ok := decodeJSONHexUnit(data, index+2)
			if !ok {
				return errors.New("invalid JSON Unicode escape")
			}
			if unit >= 0xd800 && unit <= 0xdbff {
				pair := index + 6
				if pair+6 > len(data) || data[pair] != '\\' || data[pair+1] != 'u' {
					return errors.New("unpaired high surrogate in JSON string")
				}
				low, validLow := decodeJSONHexUnit(data, pair+2)
				if !validLow || low < 0xdc00 || low > 0xdfff {
					return errors.New("unpaired high surrogate in JSON string")
				}
				index = pair + 5
				continue
			}
			if unit >= 0xdc00 && unit <= 0xdfff {
				return errors.New("unpaired low surrogate in JSON string")
			}
			index += 5
		}
	}
	return nil
}

func decodeJSONHexUnit(data []byte, start int) (uint16, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	var value uint16
	for _, character := range data[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func validateManifestJSONShape(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	if root == nil {
		return errors.New("manifest root must be an object")
	}
	if err := validateObjectKeys("manifest", root,
		[]string{"format", "version", "algorithm", "root_sha256", "payload_sha256", "normalization", "source", "entries"}, nil); err != nil {
		return err
	}
	for _, key := range []string{"format", "algorithm", "root_sha256", "payload_sha256"} {
		if err := requireJSONString("manifest."+key, root[key]); err != nil {
			return err
		}
	}
	if err := requireJSONInteger("manifest.version", root["version"]); err != nil {
		return err
	}
	var normalization map[string]json.RawMessage
	if err := json.Unmarshal(root["normalization"], &normalization); err != nil || normalization == nil {
		return errors.New("normalization must be an object")
	}
	if err := validateObjectKeys("normalization", normalization, []string{"wrapper"}, nil); err != nil {
		return err
	}
	if err := requireJSONString("normalization.wrapper", normalization["wrapper"]); err != nil {
		return err
	}
	var source map[string]json.RawMessage
	if err := json.Unmarshal(root["source"], &source); err != nil || source == nil {
		return errors.New("source must be an object")
	}
	if err := validateObjectKeys("source", source, []string{"format", "artifact_sha256"}, []string{"stripped_root"}); err != nil {
		return err
	}
	for _, key := range []string{"format", "artifact_sha256"} {
		if err := requireJSONString("source."+key, source[key]); err != nil {
			return err
		}
	}
	if raw, exists := source["stripped_root"]; exists {
		if err := requireJSONString("source.stripped_root", raw); err != nil {
			return err
		}
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(root["entries"], &entries); err != nil || entries == nil {
		return errors.New("entries must be an array")
	}
	for index, raw := range entries {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
			return fmt.Errorf("entry %d must be an object", index)
		}
		if err := validateObjectKeys(fmt.Sprintf("entry %d", index), entry,
			[]string{"path", "kind", "size", "sha256", "executable"}, nil); err != nil {
			return err
		}
		for _, key := range []string{"path", "kind", "sha256"} {
			if err := requireJSONString(fmt.Sprintf("entry %d.%s", index, key), entry[key]); err != nil {
				return err
			}
		}
		if err := requireJSONInteger(fmt.Sprintf("entry %d.size", index), entry["size"]); err != nil {
			return err
		}
		if err := requireJSONBool(fmt.Sprintf("entry %d.executable", index), entry["executable"]); err != nil {
			return err
		}
	}
	return nil
}

func requireJSONString(name string, raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return fmt.Errorf("%s must be a JSON string", name)
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return fmt.Errorf("%s must be a JSON string", name)
	}
	return nil
}

func requireJSONInteger(name string, raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("%s must be a JSON integer", name)
	}
	var value int64
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return fmt.Errorf("%s must be a JSON integer", name)
	}
	return nil
}

func requireJSONBool(name string, raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if !bytes.Equal(trimmed, []byte("true")) && !bytes.Equal(trimmed, []byte("false")) {
		return fmt.Errorf("%s must be a JSON boolean", name)
	}
	return nil
}

func validateObjectKeys(name string, object map[string]json.RawMessage, required, optional []string) error {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, exists := object[key]; !exists {
			return fmt.Errorf("%s is missing required key %q", name, key)
		}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, exists := allowed[key]; !exists {
			return fmt.Errorf("%s contains unknown or non-canonical key %q", name, key)
		}
	}
	return nil
}

type jsonContainer struct {
	kind         json.Delim
	keys         map[string]struct{}
	expectingKey bool
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	stack := make([]jsonContainer, 0, 8)
	rootDone := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if rootDone && len(stack) == 0 {
			return errors.New("trailing JSON value")
		}
		delimiter, isDelimiter := token.(json.Delim)
		if isDelimiter {
			switch delimiter {
			case '{', '[':
				if len(stack) > 0 {
					parent := &stack[len(stack)-1]
					if parent.kind == '{' && parent.expectingKey {
						return errors.New("object key must be a string")
					}
				}
				container := jsonContainer{kind: delimiter}
				if delimiter == '{' {
					container.keys = make(map[string]struct{})
					container.expectingKey = true
				}
				stack = append(stack, container)
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("unexpected closing delimiter")
				}
				container := stack[len(stack)-1]
				expected := json.Delim(']')
				if container.kind == '{' {
					expected = '}'
					if !container.expectingKey {
						return errors.New("object value is missing")
					}
				}
				if delimiter != expected {
					return errors.New("mismatched closing delimiter")
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					rootDone = true
				} else {
					parent := &stack[len(stack)-1]
					if parent.kind == '{' {
						parent.expectingKey = true
					}
				}
			}
			continue
		}
		if len(stack) == 0 {
			rootDone = true
			continue
		}
		container := &stack[len(stack)-1]
		if container.kind != '{' {
			continue
		}
		if container.expectingKey {
			key, ok := token.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if _, exists := container.keys[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			container.keys[key] = struct{}{}
			container.expectingKey = false
		} else {
			container.expectingKey = true
		}
	}
	if !rootDone || len(stack) != 0 {
		return errors.New("incomplete JSON value")
	}
	return nil
}

func ReadManifest(filename string) (Manifest, error) {
	f, err := os.Open(filename)
	if err != nil {
		return Manifest{}, fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	manifest, err := DecodeManifest(f)
	if err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// WriteManifest publishes a complete manifest without replacing an existing path.
func WriteManifest(filename string, manifest Manifest) error {
	encoded, err := encodeManifestBytes(manifest, maxManifestBytes)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("resolve manifest output: %w", err)
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create manifest directory: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".samepack-manifest-*")
	if err != nil {
		return fmt.Errorf("create temporary manifest: %w", err)
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(0o644); err != nil {
		return fmt.Errorf("set manifest permissions: %w", err)
	}
	if _, err := temp.Write(encoded); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync manifest: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close manifest: %w", err)
	}
	if err := os.Link(tempName, absolute); err != nil {
		return fmt.Errorf("publish manifest without overwrite: %w", err)
	}
	return nil
}

// ValidateManifest treats the document as untrusted input and recomputes both identities.
func ValidateManifest(manifest Manifest) error {
	if manifest.Format != ManifestFormat {
		return fmt.Errorf("unsupported format %q", manifest.Format)
	}
	if manifest.Version != ManifestVersion {
		return fmt.Errorf("unsupported manifest version %d", manifest.Version)
	}
	if manifest.Algorithm != ManifestAlgorithm {
		return fmt.Errorf("unsupported algorithm %q", manifest.Algorithm)
	}
	if !validWrapperPolicy(manifest.Normalization.Wrapper) {
		return fmt.Errorf("unsupported wrapper policy %q", manifest.Normalization.Wrapper)
	}
	if manifest.Source.Format != "tar" && manifest.Source.Format != "tar.gz" && manifest.Source.Format != "zip" {
		return fmt.Errorf("unsupported source format %q", manifest.Source.Format)
	}
	if err := validateDigest(manifest.Source.ArtifactSHA256); err != nil {
		return fmt.Errorf("source artifact digest: %w", err)
	}
	if manifest.Normalization.Wrapper == WrapperNone && manifest.Source.StrippedRoot != "" {
		return errors.New("stripped_root is set while wrapper policy is none")
	}
	if manifest.Source.StrippedRoot != "" {
		root, err := safeArchivePath(manifest.Source.StrippedRoot)
		if err != nil || root != manifest.Source.StrippedRoot || strings.Contains(root, "/") {
			return fmt.Errorf("invalid stripped_root %q", manifest.Source.StrippedRoot)
		}
	}
	if len(manifest.Entries) > maxEntries {
		return fmt.Errorf("manifest exceeds %d entries", maxEntries)
	}
	if manifest.Entries == nil {
		return errors.New("entries must be a JSON array")
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	caseFolded := make(map[string]string, len(manifest.Entries))
	var total int64
	var pathTotal int64
	previous := ""
	for index, entry := range manifest.Entries {
		name, err := safeArchivePath(entry.Path)
		if err != nil || name != entry.Path {
			if err == nil {
				err = errors.New("path is not canonical")
			}
			return fmt.Errorf("entry %d path %q: %w", index, entry.Path, err)
		}
		if index > 0 && entry.Path <= previous {
			return fmt.Errorf("entries are not strictly sorted at %q", entry.Path)
		}
		previous = entry.Path
		if err := registerPath(entry.Path, seen, caseFolded); err != nil {
			return err
		}
		if err := addPathSize(entry.Path, &pathTotal); err != nil {
			return err
		}
		if entry.Kind != "file" && entry.Kind != "symlink" {
			return fmt.Errorf("entry %q has unsupported kind %q", entry.Path, entry.Kind)
		}
		if entry.Kind == "symlink" && entry.Executable {
			return fmt.Errorf("symlink %q cannot be executable", entry.Path)
		}
		if err := checkSize(entry.Size, &total); err != nil {
			return fmt.Errorf("entry %q: %w", entry.Path, err)
		}
		if err := validateDigest(entry.SHA256); err != nil {
			return fmt.Errorf("entry %q digest: %w", entry.Path, err)
		}
	}
	if err := validatePathGraph(entriesFromManifest(manifest.Entries)); err != nil {
		return err
	}
	expectedPayload := contentRoot(entriesFromManifest(manifest.Entries))
	if manifest.PayloadSHA256 != expectedPayload {
		return fmt.Errorf("payload_sha256 does not match entries: expected %s", expectedPayload)
	}
	if err := validateDigest(manifest.PayloadSHA256); err != nil {
		return fmt.Errorf("payload digest: %w", err)
	}
	expectedRoot, err := portableRoot(manifest.Entries, manifest.Normalization.Wrapper)
	if err != nil {
		return err
	}
	if manifest.RootSHA256 != expectedRoot {
		return fmt.Errorf("root_sha256 does not match entries: expected %s", expectedRoot)
	}
	if err := validateDigest(manifest.RootSHA256); err != nil {
		return fmt.Errorf("portable root digest: %w", err)
	}
	return nil
}

// VerifyManifest compares an inspected archive to a validated baseline.
func VerifyManifest(manifest Manifest, snapshot Snapshot) (Verification, error) {
	if err := ValidateManifest(manifest); err != nil {
		return Verification{}, err
	}
	normalized, strippedRoot, err := normalizeManifestSnapshot(snapshot, manifest.Normalization.Wrapper)
	if err != nil {
		return Verification{}, err
	}
	observedEntries := manifestEntries(normalized.Entries)
	observedRoot, err := portableRoot(observedEntries, manifest.Normalization.Wrapper)
	if err != nil {
		return Verification{}, err
	}
	observedPayload := contentRoot(normalized.Entries)
	result := Verification{
		PortableIdentical:   manifest.RootSHA256 == observedRoot,
		PayloadIdentical:    manifest.PayloadSHA256 == observedPayload,
		Archive:             snapshot.Archive,
		Format:              snapshot.Format,
		ArtifactSHA256:      snapshot.ByteSHA256,
		RecordedArtifactSHA: manifest.Source.ArtifactSHA256,
		ExpectedRootSHA256:  manifest.RootSHA256,
		ObservedRootSHA256:  observedRoot,
		ExpectedPayloadSHA:  manifest.PayloadSHA256,
		ObservedPayloadSHA:  observedPayload,
		WrapperPolicy:       manifest.Normalization.Wrapper,
		StrippedRoot:        strippedRoot,
		PayloadPaths:        len(observedEntries),
		PayloadBytes:        manifestEntryBytes(observedEntries),
		Added:               []string{},
		Removed:             []string{},
		Modified:            []VerifiedPath{},
		ExecutableChanged:   []ExecutableChange{},
	}
	result.Match = result.PortableIdentical

	expected := indexManifestEntries(manifest.Entries)
	observed := indexManifestEntries(observedEntries)
	paths := make([]string, 0, len(expected)+len(observed))
	seen := make(map[string]struct{}, len(expected)+len(observed))
	for name := range expected {
		seen[name] = struct{}{}
		paths = append(paths, name)
	}
	for name := range observed {
		if _, exists := seen[name]; !exists {
			paths = append(paths, name)
		}
	}
	sort.Strings(paths)
	for _, name := range paths {
		want, wantExists := expected[name]
		got, gotExists := observed[name]
		switch {
		case !wantExists:
			result.Added = append(result.Added, name)
		case !gotExists:
			result.Removed = append(result.Removed, name)
		default:
			if want.Kind != got.Kind || want.Size != got.Size || want.SHA256 != got.SHA256 {
				result.Modified = append(result.Modified, VerifiedPath{
					Path:           name,
					ExpectedKind:   want.Kind,
					ObservedKind:   got.Kind,
					ExpectedSize:   want.Size,
					ObservedSize:   got.Size,
					ExpectedSHA256: want.SHA256,
					ObservedSHA256: got.SHA256,
				})
			}
			if want.Kind == "file" && got.Kind == "file" && want.Executable != got.Executable {
				result.ExecutableChanged = append(result.ExecutableChanged, ExecutableChange{
					Path:               name,
					ExpectedExecutable: want.Executable,
					ObservedExecutable: got.Executable,
				})
			}
		}
	}
	switch {
	case !result.PayloadIdentical:
		result.Classification = "payload_changed"
	case !result.PortableIdentical:
		result.Classification = "behavior_changed"
	default:
		result.Classification = "verified"
	}
	return result, nil
}

func normalizeManifestSnapshot(snapshot Snapshot, wrapperPolicy string) (Snapshot, string, error) {
	switch wrapperPolicy {
	case WrapperNone:
		return snapshot, "", nil
	case WrapperStripSingle:
		root, wrapped := singleArchiveRoot(snapshot.Entries)
		if !wrapped {
			return snapshot, "", nil
		}
		return stripArchiveRoot(snapshot, root), root, nil
	default:
		return Snapshot{}, "", fmt.Errorf("unsupported wrapper policy %q", wrapperPolicy)
	}
}

func validWrapperPolicy(value string) bool {
	return value == WrapperNone || value == WrapperStripSingle
}

func manifestEntries(entries []Entry) []ManifestEntry {
	result := make([]ManifestEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Kind == "directory" {
			continue
		}
		result = append(result, ManifestEntry{
			Path:       entry.Path,
			Kind:       entry.Kind,
			Size:       entry.Size,
			SHA256:     entry.SHA256,
			Executable: entry.Kind == "file" && entry.Mode&0o111 != 0,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func entriesFromManifest(entries []ManifestEntry) []Entry {
	result := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		var mode uint32
		if entry.Executable {
			mode = 0o111
		}
		result = append(result, Entry{
			Path:   entry.Path,
			Kind:   entry.Kind,
			Size:   entry.Size,
			SHA256: entry.SHA256,
			Mode:   mode,
		})
	}
	return result
}

func portableRoot(entries []ManifestEntry, wrapperPolicy string) (string, error) {
	if !validWrapperPolicy(wrapperPolicy) {
		return "", fmt.Errorf("unsupported wrapper policy %q", wrapperPolicy)
	}
	ordered := append([]ManifestEntry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	h := sha256.New()
	writeFrame(h, []byte(ManifestAlgorithm))
	writeFrame(h, []byte(wrapperPolicy))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(ordered)))
	writeFrame(h, count[:])
	for _, entry := range ordered {
		writeFrame(h, []byte(entry.Path))
		writeFrame(h, []byte(entry.Kind))
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(entry.Size))
		writeFrame(h, size[:])
		digest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return "", fmt.Errorf("entry %q has invalid digest", entry.Path)
		}
		writeFrame(h, digest)
		executable := byte(0)
		if entry.Executable {
			executable = 1
		}
		writeFrame(h, []byte{executable})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateDigest(value string) error {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return errors.New("expected 64 lowercase hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("expected 64 lowercase hexadecimal characters")
	}
	return nil
}

func indexManifestEntries(entries []ManifestEntry) map[string]ManifestEntry {
	result := make(map[string]ManifestEntry, len(entries))
	for _, entry := range entries {
		result[entry.Path] = entry
	}
	return result
}

func manifestEntryBytes(entries []ManifestEntry) int64 {
	var total int64
	for _, entry := range entries {
		total += entry.Size
	}
	return total
}
