# Real-world portable-identity corpus

Samepack's core claim is not based only on archives it produced itself. The
portable-v1 implementation was run against GitHub-generated ZIP and TAR.GZ
archives for the exact same immutable commit in 18 unrelated public projects.

## Result

- 18 commit pairs and 36 archives
- 779,161,169 compressed bytes (743.1 MiB)
- 1,607,360,907 payload bytes (1.50 GiB)
- 124,356 file/symlink paths
- 18/18 pairs had different outer SHA-256 hashes
- 18/18 pairs had the same payload hash
- 18/18 pairs had the same `samepack-portable-v1` identity, including file
  types and executable decisions

The machine-readable receipt, including every input commit URL, archive size,
outer hash, payload hash, portable root, path count, byte count, result, and
elapsed time, is [`CORPUS.json`](CORPUS.json).

## Rerun the receipt

The optional proof harness derives both archive URLs from each declared
repository and immutable commit, checks the recorded container sizes and
SHA-256 values, independently inspects ZIP and TAR.GZ, and requires both
payload and portable identities to match the receipt:

```sh
go run ./cmd/corpusproof -receipt CORPUS.json -output corpus-rerun.json
```

The full replay downloads 743.1 MiB once into a hash-checked cache. Use
`-limit 1` for a quick end-to-end check or `-cache PATH` to choose the cache.
The optional output is an atomic, no-overwrite JSON receipt containing both
observed sides. A download, hash, parse, identity, or count mismatch makes the
command fail; declared pairs are never silently skipped.

This evidence command needs network access to fetch the public corpus. The
Samepack product itself does not use a cloud API or require network access.

## Breadth

The corpus deliberately crosses languages, repository sizes, and ecosystems:

| Project | Commit | Payload paths | Portable result |
| --- | --- | ---: | --- |
| caddyserver/caddy | `502691f` | 656 | match |
| charmbracelet/gum | `4d089f9` | 115 | match |
| cli/cli | `40b742f` | 1,380 | match |
| curl/curl | `8a2bb9c` | 4,459 | match |
| git/git | `c73e853` | 4,849 | match |
| go-task/task | `01697af` | 894 | match |
| jqlang/jq | `41b8edf` | 423 | match |
| junegunn/fzf | `f7ae439` | 161 | match |
| kubernetes/kubernetes | `e72c271` | 31,279 | match |
| microsoft/vscode | `3aa5403` | 18,370 | match |
| nektos/act | `4f41128` | 2,466 | match |
| nodejs/node | `045ff95` | 51,512 | match |
| pallets/flask | `d318b68` | 236 | match |
| psf/requests | `5460f46` | 130 | match |
| python/cpython | `41b3f0a` | 6,184 | match |
| BurntSushi/ripgrep | `3fce3b5` | 237 | match |
| serde-rs/json | `afdf6fc` | 92 | match |
| sharkdp/bat | `b671e53` | 913 | match |

## Method

For each row, Samepack recorded the GitHub ZIP as a versioned manifest and then
verified the corresponding TAR.GZ without retaining or consulting the ZIP
during verification:

```text
samepack record --output baseline.samepack.json source.zip
samepack verify baseline.samepack.json source.tar.gz
```

The default exact-path policy was used. GitHub gives both formats the same
top-level wrapper for a commit, so no wrapper normalization was needed.

Each archive was read directly and every payload byte was hashed; entries were
not written to disk. Explicit directory records, timestamps, archive order,
compression, and read/write permission noise were normalized. Paths, kinds,
sizes, payload hashes, symlink targets, and regular-file executable status were
committed to the portable root.

The archive inputs are intentionally not committed because they total 743.1
MiB. Every exact commit is linked in the JSON receipt, and the proof harness
derives both generated-archive URLs from it. The elapsed
times in the receipt include separate process startup and are evidence of the
completed run, not a controlled performance benchmark.

GitHub documents why this matters: generated source archives may be recreated
with different compression while their extracted contents remain the same.
See [Downloading source code archives](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives).
