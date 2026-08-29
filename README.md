# Samepack

Two release archives have different hashes. Is it a harmless timestamp, a different file order, or an actual changed file?

Samepack answers that question without extracting either archive. It can also build canonical `tar`, `tar.gz`, and `zip` releases whose bytes do not depend on source timestamps, file-system order, user IDs, or the host operating system.

```text
$ samepack compare release-linux.tar.gz release-windows.zip
CONTENT IDENTICAL — raw bytes differ only in packaging metadata or encoding
reason    archive format changed (tar.gz -> zip)

$ samepack compare app-1.0.tar.gz app-1.1.tar.gz
CONTENT CHANGED — 1 added, 0 removed, 1 modified path(s)
+ SECURITY.txt
~ config/app.json  36ead586bce6 -> 88782e27e4bf
```

This project is being built for the 2026 Zero Dependency Hackathon, Track A: Developer Tools & CLI.

AI-assisted development: ChatGPT/Codex was used as development tooling.

## Build

```sh
go build -trimpath -o dist/samepack ./cmd/samepack
```

There is no dependency download step. [`go.mod`](go.mod) contains no `require` block.
The captured [`deps-proof.txt`](deps-proof.txt) output contains only this module.

## Use

```sh
# Build a canonical release archive.
samepack pack --output release.tar.gz ./dist

# Explain two different archive hashes.
samepack compare release-linux.tar.gz release-windows.tar.gz

# Get stable JSON for CI.
samepack compare --json release-a.zip release-b.zip

# Inspect without extracting.
samepack inspect release.tar.gz
```

`compare` exits `0` when content is identical, even if packaging metadata differs. It exits `3` when content changed and prints up to 50 added, removed, or modified paths. Use `--max-changes 0` for every path; JSON output is never truncated. Invalid or unsafe archives exit `1`.

When two release archives use different single top-level directories (for
example `app-1.0/` and `app-1.1/`), Samepack ignores those wrappers and compares
the payload paths underneath them.

## Evidence, not claims

- [`CASE_STUDIES.md`](CASE_STUDIES.md) records checks against real GitHub release
  archives, including one compatibility bug the check exposed and fixed.
- [`DEMO.md`](DEMO.md) is the complete five-minute judge flow.
- [`REPRODUCIBLE.md`](REPRODUCIBLE.md) records byte-identical output from the
  Windows and Linux executables.
- [`STDLIB.md`](STDLIB.md) documents 12 concrete standard-library substitutions.
- [`.github/workflows/verify.yml`](.github/workflows/verify.yml) repeats tests,
  dependency proof, same-OS reproducibility, and cross-OS reproducibility.

## Current safety boundary

- Inspection never extracts files.
- Absolute paths, parent traversal, backslashes, duplicate names, case-colliding names, oversized entries, and unsupported special entries are rejected.
- Packing accepts regular files and directories. Symbolic links and special files are rejected rather than interpreted differently across operating systems.
- Output must be outside the source directory, and Samepack refuses to overwrite an existing archive.
- Final publication uses a same-directory hard link so no-overwrite is atomic; the output filesystem must support hard links.
- Samepack identifies content changes; it does not authenticate who produced an archive. Sign the published SHA-256 through your normal release process.

## Verify

```sh
go test ./...
go vet ./...
go list -m all
```

`go list -m all` must print only `github.com/LubuSeb/samepack`.

The Windows-versus-Linux archive hashes and exact output are published in
[`REPRODUCIBLE.md`](REPRODUCIBLE.md).

## Licence

[MIT](LICENSE)
