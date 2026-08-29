# Five-minute demo

This is the shortest path through Samepack's user value and hackathon proof.
It is intentionally a terminal demo: Samepack is a release-engineering CLI and
its exit codes and stdout are part of the product.

## 1. The problem (30 seconds)

Open with two archives whose SHA-256 values differ. A raw hash cannot say
whether the payload changed or whether a packer merely changed timestamps,
entry order, modes, or container format.

## 2. Harmless difference (60 seconds)

```powershell
go build -trimpath -o dist\samepack.exe .\cmd\samepack
.\dist\samepack.exe pack --output dist\demo-v1.tar.gz .\demo\release-v1
.\dist\samepack.exe pack --output dist\demo-v1.zip --format zip .\demo\release-v1
.\dist\samepack.exe compare dist\demo-v1.tar.gz dist\demo-v1.zip
```

The raw hashes differ, but Samepack returns `0`, prints one shared logical
content hash, and explains the archive-format and timestamp differences.

## 3. Real payload change (60 seconds)

```powershell
.\dist\samepack.exe pack --output dist\demo-v2.tar.gz .\demo\release-v2-changed
.\dist\samepack.exe compare dist\demo-v1.tar.gz dist\demo-v2.tar.gz
```

Samepack returns `3` and identifies `SECURITY.txt` as added and
`config/app.json` as modified. Nothing is extracted to disk.

## 4. Reproducible output (60 seconds)

Show the passing `cross-os-proof` job in GitHub Actions. Windows and Linux each
pack the fixture twice after a source timestamp change. The final job downloads
both outputs and runs `sha256sum` plus `cmp`.

The published local receipt is [`REPRODUCIBLE.md`](REPRODUCIBLE.md).

## 5. Zero-dependency receipts (45 seconds)

```powershell
go list -m all
go test ./...
go vet ./...
```

The module command prints only `github.com/LubuSeb/samepack`. Then show the
empty `require` section in `go.mod`, the 12 real substitutions in `STDLIB.md`,
and the safety tests for traversal, control characters, malformed archives,
case collisions, symlinks, size caps, and no-overwrite publication.

## 6. Real-world evidence and boundary (45 seconds)

Close on [`CASE_STUDIES.md`](CASE_STUDIES.md): the same ripgrep 14.1.1 source
tag in GitHub TAR.GZ and ZIP is correctly classified as identical content, while
14.1.0 versus 14.1.1 produces one addition, one removal, and 39 modified paths.

Be explicit about the boundary: Samepack proves payload equality and explains
packaging differences. It does not authenticate the producer; release hashes
should still be signed through the user's normal release process.
