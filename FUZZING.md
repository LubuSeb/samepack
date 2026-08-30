# Adversarial and property proof

Samepack's trust boundary consumes untrusted archive and manifest bytes. Four
native Go fuzz targets exercise that boundary without third-party frameworks.
The public workflow gives each target a fresh 10-second budget on Ubuntu; these
commands reproduce the same proof locally:

```sh
go test ./internal/archiveio -run=^$ -fuzz=^FuzzInspectNeverPanics$ -fuzztime=10s -parallel=2
go test ./internal/archiveio -run=^$ -fuzz=^FuzzDecodeManifestStrict$ -fuzztime=10s -parallel=2
go test ./internal/archiveio -run=^$ -fuzz=^FuzzRecordVerifyCrossFormat$ -fuzztime=10s -parallel=2
go test ./internal/archiveio -run=^$ -fuzz=^FuzzVerifyPinpointsMutation$ -fuzztime=10s -parallel=2
```

## What each property proves

- `FuzzInspectNeverPanics` feeds arbitrary ZIP, TAR, GZIP, junk, and truncated
  bytes through the production readers under injected resource ceilings. A
  successful parse must be deterministic, safe, internally consistent, and
  within every entry/path/expanded-byte bound.
- `FuzzDecodeManifestStrict` mutates untrusted JSON. Anything accepted must
  validate, encode deterministically, and survive an exact typed round trip.
- `FuzzRecordVerifyCrossFormat` generates bounded payloads and executable
  decisions, writes independent ZIP and TAR.GZ representations, records one,
  and requires the other to verify under both wrapper policies.
- `FuzzVerifyPinpointsMutation` injects an addition, removal, byte change, or
  executable change and requires the exact affected path in the result.

The deterministic suite complements coverage-guided mutation with fixtures for
every truncated GZIP prefix, a corrupt GZIP checksum, an expanded trailing
bomb, traversal/absolute/control paths, duplicate and case-varied paths,
file-as-directory ancestors, privileged/special file kinds, size ceilings,
ambiguous JSON keys, invalid UTF-8 and UTF-16 escapes, and no-overwrite races.

## Captured local run

On 30 August 2026 with Go 1.26.5 on Windows/amd64, one sequential 10-second run
per target completed without a failure:

| Target | Executions reported by Go |
| --- | ---: |
| archive parsing | 168,223 |
| strict manifest decoding | 4,225 |
| cross-format record/verify | 1,045 |
| exact mutation diagnosis | 225,673 |
| **Total** | **399,166** |

Execution counts depend on hardware, scheduler, corpus cache, and discovered
inputs; they are a dated receipt, not a promised throughput benchmark. The CI
time budgets and deterministic regression fixtures are the lasting proof.
