# Contributing to cipherlint

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — the tool, its tests and the smoke script
are fully offline.

```bash
git clone https://github.com/JaydenCJ/cipherlint && cd cipherlint
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives it end-to-end over the four
example configs (nginx, Apache, HAProxy, Caddy), asserting on findings,
citations, exit codes, output formats and dated-profile resolution; it must
finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (90 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (parsers, expansion and lint rules never touch the filesystem —
   only `internal/cli` does I/O).

## Ground rules

- Keep dependencies at zero — cipherlint is standard library only, and the
  point of the tool is that it runs anywhere, offline. No network calls, no
  telemetry, ever.
- **Policy is data, and dated tables are immutable.** Never edit a shipped
  `name@date` edition; changed advice lands as a new date in
  `internal/policy/policy.go` with its reasoning documented in
  `docs/rules.md`. Every new rule needs a catalog entry
  (`internal/lint/rules.go`) with a citation.
- New cipher suites go into `internal/ciphers/table.go` with both the
  OpenSSL and IANA name, plus a test.
- Code comments and doc comments are written in English.
- Determinism first: identical input must produce byte-identical reports,
  including all orderings.

## Reporting bugs

Include the output of `cipherlint version`, the full command you ran, the
minimal config snippet that reproduces the problem (redact hostnames if
needed), and — for wrong-expansion reports — the output of
`openssl ciphers -v '<your string>'` from your server, since that is the
ground truth the evaluator is modeled on.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
