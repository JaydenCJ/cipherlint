# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Static, offline TLS-config linting for four dialects: nginx (directive
  grammar with http→server inheritance and conf.d snippet support), Apache
  httpd (vhost containers, additive `SSLProtocol` syntax, line
  continuations), HAProxy (global `ssl-default-bind-*` merged with per-bind
  overrides, `ssl-min-ver`/`no-*` options, `tune.ssl.default-dh-param`) and
  Caddyfile (site blocks, `tls` subdirectives, header forms), plus
  content-based dialect auto-detection with a `--server` override.
- An OpenSSL cipher-string evaluator (`!` / `-` / `+` operators, infix
  intersections, `@STRENGTH`, ~30 keywords) over a curated offline table of
  ~50 suites with OpenSSL and IANA names, documented in
  docs/cipher-strings.md; unknown tokens are reported instead of silently
  ignored.
- Dated, versioned policy tables addressable as `name@date`
  (`modern` / `intermediate` / `old` × `2023-10` / `2026-01`); bare names
  resolve to the newest edition, shipped editions are never rewritten, and
  the 2026-01 tables retire the OCSP-stapling recommendation.
- A 15-rule catalog (CL001–CL015) covering protocols, broken and legacy
  ciphers, forward secrecy, cipher ordering, session tickets, DH parameters,
  curves, HSTS and OCSP stapling — every finding carries a citation
  (RFC, CVE or table edition), and documented server defaults are linted as
  implicit settings.
- CLI with `lint` (text, JSON `schema_version: 1`, and Markdown output;
  `--fail-on` severity gate; exit codes 0/1/2/3), `profiles`, and
  `explain <rule>` subcommands.
- Runnable example configs for all four dialects, a pinned-profile CI gate
  script (`examples/ci-gate.sh`), and reference docs (`docs/rules.md`,
  `docs/cipher-strings.md`).
- 90 deterministic offline tests (expansion, four parsers, detection,
  policy resolution, lint rules, renderers, in-process CLI integration) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/cipherlint/releases/tag/v0.1.0
