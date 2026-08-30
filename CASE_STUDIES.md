# Samepack in real release archives

Small fixtures prove edge cases. They do not prove that a portable archive
identity survives real repositories, formats, and scale. Samepack therefore
records and verifies archives it did not create.

## 18 repositories, 36 archives, one result

For each of 18 unrelated public repositories, GitHub's generated ZIP was
recorded as a manifest. The matching TAR.GZ for the exact same immutable commit
was then verified using only that manifest and the TAR.GZ:

```text
samepack record --output baseline.samepack.json source.zip
samepack verify baseline.samepack.json source.tar.gz
```

Across the completed run:

- 18 commit pairs and 36 archives were processed.
- The compressed inputs totalled 779,161,169 bytes (743.1 MiB).
- Samepack hashed 124,356 file and symlink paths.
- Every pair had different outer SHA-256 hashes.
- Every pair had matching payload roots.
- Every pair had matching `samepack-portable-v1` roots, including entry kinds
  and executable decisions.

All 18 declared pairs were processed; none was skipped, and all 18 matched.

## Breadth, not one convenient fixture

The input ranges from small libraries to large, mixed-platform repositories:

| Project | Payload paths | Result |
| --- | ---: | --- |
| serde-rs/json | 92 | portable match |
| charmbracelet/gum | 115 | portable match |
| cli/cli | 1,380 | portable match |
| git/git | 4,849 | portable match |
| python/cpython | 6,184 | portable match |
| microsoft/vscode | 18,370 | portable match |
| kubernetes/kubernetes | 31,279 | portable match |
| nodejs/node | 51,512 | portable match |

The full 18-project table and methodology are in [`CORPUS.md`](CORPUS.md).
[`CORPUS.json`](CORPUS.json) records every immutable commit URL, input byte
count, outer hash, payload hash, portable root, path count, and result.

GitHub documents the reason for the test: generated source archives can be
recreated with different compression, changing the archive checksum without
changing the extracted contents. See
[Downloading source code archives](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives).

## A negative control that names the damage

A verifier must also fail usefully. The committed demo fixtures change
`config/app.json` and add `SECURITY.txt`. A manifest recorded from the first ZIP
rejects the changed TAR.GZ:

```text
PAYLOAD MISMATCH — 1 added, 0 removed, 1 modified
+ SECURITY.txt
~ config/app.json  36ead586bce6 -> 88782e27e4bf
```

Exit code: `3`.

The result is not a boolean guess. It carries the expected and observed
artifact, payload, and portable roots, plus sorted path-level changes. A change
from a regular file to a symlink is reported as a kind change. A change to the
executable bit is isolated as a behavior mismatch even when the file bytes are
unchanged.

## The baseline survives without the original archive

The manifest contains sorted path records, per-entry SHA-256 values, kinds,
sizes, executable decisions, the normalization policy, and its recomputed
portable root. Once `record` finishes, the source archive can be discarded.
`verify` reads the manifest and candidate archive only.

Different ZIP/TAR encoding, timestamps, archive order, explicit directory
records, and read/write permission noise do not cause false mismatches. Wrapper
removal is not automatic: `record --strip-root` must opt into that policy, and
the choice is persisted in the manifest.

## A compatibility bug this work caught

The first real GitHub TAR.GZ run was rejected because it contains a POSIX global
PAX metadata record. That record is packaging metadata, not a released path.
Samepack now handles it explicitly with a regression test while continuing to
reject unknown TAR special-entry types.

That is why the corpus matters: it tested the archive reader against formats
and metadata emitted by a production platform, rather than only against
Samepack's own canonical writer.

## What the result does not prove

Samepack proves equality to the supplied manifest. It does not establish who
published the manifest, replace a signature, or provide provenance. The user
must obtain the baseline through a trusted channel and commit or sign it. No
archive entry is written to disk during recording or verification.
