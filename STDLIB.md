# Standard-library substitution log

Samepack has no third-party runtime or test dependencies. These are real design substitutions made in the implementation, not hypothetical package names added to fill a list.

| Need | A typical dependency | Samepack uses | Why |
| --- | --- | --- | --- |
| CLI flags and subcommands | Cobra | `flag` | Separate `FlagSet` values keep parsing small and explicit. |
| Recursive file discovery | Afero or doublestar | `path/filepath.WalkDir` and `io/fs` | The source tree needs deterministic walking, not virtual filesystems or glob syntax. |
| TAR streams | archiver | `archive/tar` | Samepack writes every canonical header itself. |
| ZIP streams | archiver | `archive/zip` | Header timestamps, modes, methods, and order stay under our control. |
| Gzip compression | a compression wrapper | `compress/gzip` | The gzip header and compression level can be normalized directly. |
| Content hashing | xxhash or a digest helper | `crypto/sha256` and `encoding/hex` | SHA-256 is portable, reviewable, and suitable for release evidence. |
| Directory/content comparison | go-cmp | A sorted merge over typed entry records | The user needs path-level changes, not reflection-based structural diffs. |
| Canonical content root | a Merkle-tree package | `crypto/sha256` plus length-prefixed framing | Length prefixes make the digest input unambiguous without a serialization dependency. |
| Machine-readable output | a JSON helper | `encoding/json` | Typed structs already provide stable field names and arrays. |
| Cross-platform path policy | a safe-path package | `path`, `filepath`, and explicit validation | Archive paths and host paths have different semantics, so the boundary is visible in code. |
| Atomic output | an atomic-file package | `os.CreateTemp`, `File.Sync`, and `os.Rename` | A failed pack never leaves a completed-looking artifact. |
| Test fixtures and assertions | Testify and fixture packages | `testing`, `archive/tar`, `archive/zip`, and ordinary helpers | The tests construct adversarial archives directly and use no hidden machinery. |

## Deliberate limits

- Samepack does not shell out to `tar`, `zip`, `diff`, or any separately installed program.
- It does not vendor source code from another project.
- It does not implement cryptographic signatures; it emits hashes intended for an existing signed release process.
