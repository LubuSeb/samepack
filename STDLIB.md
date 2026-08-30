# Standard-library substitution log

Samepack has no third-party runtime or test dependencies. The manifest
workflow, archive readers, canonical writer, CLI, corpus receipt, and tests are
implemented with Go's standard library. These are concrete substitutions made
in the code, not package names added to fill a list.

| Need | A typical dependency | Samepack uses | Why |
| --- | --- | --- | --- |
| CLI flags and subcommands | Cobra | `flag` | Separate `FlagSet` values keep parsing small and every exit path explicit. |
| Recursive file discovery | Afero or doublestar | `path/filepath.WalkDir` and `io/fs` | The source tree needs deterministic walking, not virtual filesystems or glob syntax. |
| TAR streams | archiver | `archive/tar` | Entries are inspected in memory and canonical headers remain under Samepack's control. |
| ZIP streams | archiver | `archive/zip` | Header timestamps, modes, methods, and order can be normalized directly. |
| Gzip compression | a compression wrapper | `compress/gzip` | The gzip header and compression level can be fixed without an adapter. |
| Streaming payload verification | an extraction or virtual-filesystem package | `io`, `archive/tar`, `archive/zip`, and `crypto/sha256` | Every payload byte is hashed while streaming; entries are never written to disk. |
| Content hashing | xxhash or a digest helper | `crypto/sha256` and `encoding/hex` | SHA-256 is portable, reviewable, and appropriate for release evidence. |
| Portable archive identity | a Merkle-tree package | `crypto/sha256` plus length-prefixed binary framing | `samepack-portable-v1` commits unambiguously to path, kind, size, digest, executable status, and wrapper policy. |
| Versioned manifest encoding | a serialization framework | `encoding/json` with typed structs | The receipt is deterministic, reviewable, and stable without generated code. |
| Strict manifest parsing | a JSON Schema validator | `encoding/json.Decoder`, a token pass, and explicit invariants | Duplicate and unknown fields, trailing values, invalid UTF-8, unsafe paths, bad versions, and inconsistent roots are rejected. |
| Directory/content comparison | go-cmp | A sorted merge over typed entry records | The user receives exact added, removed, modified, kind-changed, and executable-changed paths. |
| Cross-platform path policy | a safe-path package | `path`, `filepath`, `strings`, and explicit validation | Archive paths and host paths have different semantics, so their boundary stays visible in code. |
| Machine-readable CLI and corpus output | a JSON helper | `encoding/json` | Typed result structs make CI output complete and untruncated. |
| Atomic, no-overwrite publication | an atomic-file package | `os.CreateTemp`, `File.Sync`, and `os.Link` | A failed write cannot leave a completed-looking receipt or replace a racing destination. |
| Fuzzing malformed inputs | a fuzzing framework | Go's native `testing.F` | The same parser and archive code are exercised with generated invalid and representation-varying inputs. |
| Test fixtures and assertions | Testify and fixture packages | `testing`, `archive/tar`, `archive/zip`, and ordinary helpers | Tests construct adversarial archives directly, with no hidden assertion or fixture machinery. |

## What the standard library made possible

The zero-dependency constraint shaped the architecture:

- `record` converts an archive stream into a versioned, sorted manifest.
- `verify` recomputes both payload and portable roots from a candidate stream.
- `samepack-portable-v1` ignores timestamps, order, compression, explicit
  directory records, and read/write permission noise while preserving path,
  kind, size, digest, and executable behavior.
- `record --strip-root` is an explicit policy, persisted in the manifest rather
  than inferred differently on each verification.
- The strict reader recomputes both roots instead of trusting digest fields in
  an edited manifest.

## Deliberate limits

- Samepack does not shell out to `tar`, `zip`, `diff`, or another installed
  program.
- It does not use a cloud API at runtime or vendor code from another project.
- `record`, `verify`, `compare`, and `inspect` do not extract archive entries to
  disk.
- It does not implement publisher identity, signatures, or provenance. The
  manifest must be obtained through a trusted channel and committed or signed
  through the user's release process.
- Packing rejects symlinks and special files; inspection and portable identity
  support regular files and symlinks while rejecting unsafe and unknown kinds.
