# Samepack

[![verify](https://github.com/LubuSeb/samepack/actions/workflows/verify.yml/badge.svg)](https://github.com/LubuSeb/samepack/actions/workflows/verify.yml)

## Lock the files, not the compression

GitHub can regenerate a source archive with different compression. Its SHA-256
changes even when every released file stays the same. Samepack records a small,
reviewable payload manifest once, then verifies later ZIP, TAR, or TAR.GZ
archives against it—without retaining the original archive and without writing
archive entries to disk.

```text
$ samepack record --output release.samepack.json release.zip
RECORDED — portable payload baseline written
paths     3 files/symlinks
artifact  sha256:892c5143c66d453fc4e7cdaeed900469190b186956d69f8f19cd3c73996747c9
payload   sha256:bc93a3462a490cbc9a00d4b223ce18d828849d3c08ea7cbc496ba6c6699578f4
portable  sha256:0f09cce3ae7a5270083dbf46afd5b25f882406f02c5c466a11cf45da7c5cc131
next      commit or sign the manifest before trusting it

$ samepack verify release.samepack.json regenerated-release.tar.gz
PAYLOAD VERIFIED — 3 paths match despite different archive bytes
note      archive bytes differ; payload and executable behavior match

$ samepack verify release.samepack.json changed-release.tar.gz
PAYLOAD MISMATCH — 1 added, 0 removed, 1 modified
+ SECURITY.txt
~ config/app.json  36ead586bce6 -> 88782e27e4bf
```

The first verification exits `0`. The changed archive exits `3` and names the
affected paths. The recorded ZIP is not consulted during either verification.

This project is being built for the 2026 Zero Dependency Hackathon, Track A:
Developer Tools & CLI.

ChatGPT/Codex was used as development tooling.

## Real-world proof

Samepack was run against GitHub-generated ZIP and TAR.GZ archives for the exact
same immutable commit in 18 unrelated repositories:

- 18 commit pairs and 36 archives
- 743.1 MiB of compressed input
- 124,356 file and symlink paths
- 18/18 pairs had different outer SHA-256 hashes
- 18/18 pairs had matching payload and `samepack-portable-v1` roots

The corpus includes CPython, Git, Kubernetes, Node.js, ripgrep, VS Code, and
twelve more projects. [`CORPUS.md`](CORPUS.md) explains the method;
[`CORPUS.json`](CORPUS.json) is the machine-readable receipt with every commit,
input hash, result, and elapsed time.

This is the documented failure mode Samepack targets: GitHub notes that a
generated source archive may be recreated with different compression while its
extracted contents remain the same. See
[Downloading source code archives](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives).

## Build the current source

Go 1.26 or newer is required.

```sh
go build -trimpath -o dist/samepack ./cmd/samepack
```

There is no dependency download step. [`go.mod`](go.mod) contains no `require`
block, and [`deps-proof.txt`](deps-proof.txt) contains only this module.

Manifest-capable prebuilt binaries may be downloaded from
[the latest release](https://github.com/LubuSeb/samepack/releases/latest) once a
corresponding release is published. Until then, build the current source above.

## Record once, verify later

Record the archive you trust and commit or sign the resulting manifest:

```sh
samepack record --output release.samepack.json source.zip
```

Verify one regenerated archive, or a whole release set, without the original:

```sh
samepack verify release.samepack.json source.tar.gz
samepack verify release.samepack.json mirror.zip mirror.tar source.tar.gz
```

For CI, both commands support JSON output:

```sh
samepack record --json --output release.samepack.json source.zip
samepack verify --json release.samepack.json mirror.zip mirror.tar.gz
```

By default, paths must match exactly. If versioned archives use different
single top-level directories such as `project-1.0/` and `project-1.1/`, make
wrapper removal an explicit, persisted policy when recording:

```sh
samepack record --strip-root --output release.samepack.json project-1.0.zip
samepack verify release.samepack.json project-1.1.tar.gz
```

`--strip-root` is opt-in. Samepack does not silently hide a renamed root.

## What `samepack-portable-v1` means

The portable root commits to each sorted payload entry's:

- normalized path
- kind (`file` or `symlink`)
- size
- SHA-256 of file bytes or symlink-target bytes
- executable status for regular files

It deliberately ignores compression, container format, archive order,
timestamps, explicit directory records, and read/write permission noise.
Executable changes are not dismissed as metadata: they produce a behavior
mismatch and exit `3`.

The manifest is deterministic, versioned JSON. Its strict reader rejects
duplicate or unknown fields, trailing JSON values, invalid UTF-8, unsafe or
unsorted paths, unsupported versions and algorithms, non-canonical digests,
and roots that do not recompute from the entries. Existing manifest files are
never overwritten.

## Secondary tools

The persistent manifest is the primary workflow. Samepack also retains its
archive investigation and reproducible-packing commands:

```sh
# Compare two archives directly and explain changed paths.
samepack compare release-a.zip release-b.tar.gz

# Inspect an archive without extracting it.
samepack inspect release.tar.gz

# Build a canonical tar, tar.gz, or zip release.
samepack pack --output release.tar.gz ./dist
# Opt in only when source executable status is part of the release payload.
samepack pack --preserve-executable --output release.tar.gz ./dist
```

By default, `pack` normalizes regular files to `0644` and directories to `0755`,
along with timestamps, ordering, ownership, compression headers, and
host-specific path behavior. For the same representable source tree and Go
toolchain, this is the cross-platform reproducible mode, and the command
discloses it on stderr. Compression output may change across Go toolchain
versions. `--preserve-executable` instead maps source
files exposed as executable by the host filesystem to `0755`; use that when
launchability is part of the release, accepting that filesystems such as Windows
may not expose POSIX executable status consistently.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The command succeeded, or every verified portable payload matched. |
| `1` | A manifest or archive was invalid, unsafe, unreadable, or could not be processed. |
| `3` | A valid archive changed payload, entry kind, or executable behavior. |

Human output prints at most 50 changes by default. Use `--max-changes 0` to
show all paths. JSON verification output is complete and untruncated.

## Safety and trust boundary

- `record`, `verify`, `compare`, and `inspect` stream archive contents; they do
  not extract entries to disk.
- Absolute paths, paths that escape the archive root, backslashes, control characters, duplicate
  paths, obvious case-only collisions, oversized entries, and unsupported special
  entries are rejected.
- Samepack does not claim that an accepted path can be extracted safely on every
  host filesystem. Unicode normalization aliases and platform-reserved names
  remain host-specific; the core workflow never extracts archive entries.
- Inspection is bounded to 100,000 archive records, 1 GiB per payload entry,
  4 GiB of total payload bytes, 32 MiB of path text, and about 4.57 GiB of raw
  or expanded container bytes. These are safety ceilings, not tuning flags.
- Packing accepts regular files and directories. It rejects symbolic links and
  special files instead of interpreting them differently across platforms.
- Output must be outside the source directory. Samepack refuses to overwrite an
  archive or manifest and publishes completed files atomically with a
  same-directory hard link.
- A manifest is a baseline, not an identity. Samepack proves equality to the
  manifest you supplied; it does not authenticate who created that manifest or
  archive. Commit or sign the manifest through the normal release process.

## Evidence index

- [`CASE_STUDIES.md`](CASE_STUDIES.md): real corpus results, negative proof, and
  the archive compatibility bug the work exposed
- [`DEMO.md`](DEMO.md): the 2.5–3 minute judge flow
- [`CORPUS.md`](CORPUS.md) and [`CORPUS.json`](CORPUS.json): rerunnable
  real-project evidence and its machine-readable receipt
- [`FUZZING.md`](FUZZING.md): four native fuzz properties, adversarial fixtures,
  exact commands, and a dated local execution receipt
- [`REPRODUCIBLE.md`](REPRODUCIBLE.md): byte-identical pack output from Windows
  and Linux
- [`STDLIB.md`](STDLIB.md): concrete standard-library substitutions
- [`.github/workflows/verify.yml`](.github/workflows/verify.yml): tests,
  dependency proof, and reproducibility checks

## Verify the source

```sh
go test ./...
go vet ./...
go list -m all
```

`go list -m all` must print only `github.com/LubuSeb/samepack`.

## Licence

[MIT](LICENSE)
