# 2.5–3 minute judge demo

The story is one sentence: **lock the files, not the compression**. Show a
checksum mismatch, save a trusted portable baseline, verify a differently
packed archive, then make the verifier fail on a real payload change.

## Prepare before recording

Run these commands from a clean checkout. They create fresh artifacts in a
unique temporary directory so Samepack's no-overwrite protection remains part
of the demonstration.

```powershell
$demo = Join-Path $env:TEMP ("samepack-judge-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $demo | Out-Null
$samepack = Join-Path $demo "samepack.exe"

go build -trimpath -o $samepack .\cmd\samepack
& $samepack pack --output (Join-Path $demo "release-v1.zip") --format zip .\demo\release-v1
& $samepack pack --output (Join-Path $demo "release-v1.tar.gz") --format tar.gz .\demo\release-v1
& $samepack pack --output (Join-Path $demo "release-v2-changed.tar.gz") --format tar.gz .\demo\release-v2-changed
```

Keep the terminal font large. Clear the terminal before the timed flow.

## 0:00–0:25 — The checksum tells us only that bytes changed

```powershell
Get-FileHash (Join-Path $demo "release-v1.zip"), (Join-Path $demo "release-v1.tar.gz")
```

The SHA-256 values differ. Say: “That could be different compression, or it
could be a changed release file. A raw checksum cannot distinguish them.”

## 0:25–1:05 — Record once, verify without the original

```powershell
& $samepack record --output (Join-Path $demo "release.samepack.json") (Join-Path $demo "release-v1.zip")
& $samepack verify (Join-Path $demo "release.samepack.json") (Join-Path $demo "release-v1.tar.gz")
```

Point to `PAYLOAD VERIFIED`, the different recorded and observed artifact
hashes, and the shared payload hash. Say: “Verification receives the manifest
and candidate TAR.GZ only. It does not reopen or extract the ZIP.”

Open the first few lines of the receipt:

```powershell
Get-Content (Join-Path $demo "release.samepack.json") -TotalCount 18
```

Point out the versioned algorithm and readable path records. The manifest is
small enough to review, commit, or sign.

## 1:05–1:40 — Change one file and fail precisely

```powershell
& $samepack verify (Join-Path $demo "release.samepack.json") (Join-Path $demo "release-v2-changed.tar.gz")
$LASTEXITCODE
```

The output names the added `SECURITY.txt`, the modified `config/app.json`, and
returns `3`. Say: “Samepack also fails on file-kind and executable changes;
read/write permission noise is normalized.”

## 1:40–2:15 — Replace the toy claim with real evidence

```powershell
Get-Content .\CORPUS.md -TotalCount 24
```

Land on the numbers:

- 18 unrelated repositories
- 36 GitHub-generated archives
- 743.1 MiB compressed input
- 124,356 file and symlink paths
- all 18 outer hash pairs differed
- all 18 portable roots matched

Show [`CORPUS.json`](CORPUS.json) briefly. It contains immutable commit URLs and
both input hashes for every result; it is a receipt, not a screenshot.

## 2:15–2:45 — Prove the constraint and state the boundary

```powershell
go list -m all
go test ./...
```

`go list -m all` prints only `github.com/LubuSeb/samepack`. Mention that
recording and verification are built from `archive/tar`, `archive/zip`,
`compress/gzip`, `crypto/sha256`, and `encoding/json`; no shell tools, cloud
services, or third-party modules are required.

Close with the honest boundary:

> Samepack proves that an archive matches the manifest you trust. It does not
> authenticate the publisher, so commit or sign that manifest through your
> normal release process.

## Optional 15-second appendix

If time remains, show the secondary commands only:

```powershell
& $samepack compare (Join-Path $demo "release-v1.zip") (Join-Path $demo "release-v1.tar.gz")
& $samepack inspect (Join-Path $demo "release-v1.tar.gz")
```

Mention that `pack` also creates byte-reproducible TAR, TAR.GZ, and ZIP outputs
for the same representable source tree and Go toolchain; the cross-OS receipt
is in [`REPRODUCIBLE.md`](REPRODUCIBLE.md).
