# Reproducibility receipt

Samepack's demo release was packed independently by the Windows and Linux
executables on 29 August 2026. The resulting `tar.gz` files were byte-for-byte
identical.

| Producer | Runtime | Artifact SHA-256 | Logical content SHA-256 |
| --- | --- | --- | --- |
| `samepack.exe` | Windows amd64 | `a1c79772b6f676cdb16a0814d44fa07f7b4313753562901c87b338b4358a67be` | `bc93a3462a490cbc9a00d4b223ce18d828849d3c08ea7cbc496ba6c6699578f4` |
| `samepack-linux-amd64` | Ubuntu/WSL2 amd64 | `a1c79772b6f676cdb16a0814d44fa07f7b4313753562901c87b338b4358a67be` | `bc93a3462a490cbc9a00d4b223ce18d828849d3c08ea7cbc496ba6c6699578f4` |

Both executables were built from the same source with Go 1.26.5 and
`-trimpath`. The Linux binary was then executed under Ubuntu, reading the same
fixture through the WSL mount. Source-file timestamps had also been shifted by
17 days between two Windows runs; those archives produced the same artifact
hash again.

The relevant commands were:

```text
samepack.exe pack --output windows.tar.gz demo/release-v1
samepack-linux-amd64 pack --output linux.tar.gz demo/release-v1
samepack.exe compare windows.tar.gz linux.tar.gz
```

The comparison result was:

```text
BYTE IDENTICAL — the archives have the same SHA-256
before    sha256:a1c79772b6f676cdb16a0814d44fa07f7b4313753562901c87b338b4358a67be
after     sha256:a1c79772b6f676cdb16a0814d44fa07f7b4313753562901c87b338b4358a67be
content   sha256:bc93a3462a490cbc9a00d4b223ce18d828849d3c08ea7cbc496ba6c6699578f4
```

This receipt covers the archive produced by Samepack. Executables for different
operating systems are expected to have different bytes.

The verification workflow also builds the Samepack executable twice on each
runner and compares the binaries before testing archive output. Its passing CI
run is the current binary-reproducibility receipt for each commit.
