# cipherlint rules and policy tables

This document is the normative reference for the rule catalog and the dated
policy tables. `cipherlint explain <rule>` prints the same text the catalog
holds; this page adds the reasoning.

## Severities

| Severity | Meaning | Default gate |
|---|---|---|
| `error` | An attacker can exploit this today (RC4, 3DES, TLS 1.0, 1024-bit DH, weak curves). | fails the run |
| `warning` | Violates the selected profile (CBC suites under `intermediate`, short HSTS, tickets on). | passes unless `--fail-on warning` |
| `info` | Recommendation or informational note (missing HSTS, cipher-order preference, dated OCSP advice, unknown tokens). | passes unless `--fail-on info` |

## Rule catalog

| Rule | Title | Severity | Primary citation |
|---|---|---|---|
| CL001 | obsolete protocol enabled | error (`old`: warning for TLS 1.0/1.1) | RFC 8996 (2021-03); RFC 7568; RFC 6176 |
| CL002 | protocol below profile floor | warning | profile table |
| CL003 | TLS 1.3 not enabled | warning | RFC 8446 (2018-08) |
| CL004 | broken cipher suite reachable | error | RFC 7465; CVE-2016-2183; CVE-2015-0204 |
| CL005 | legacy CBC/HMAC cipher suite | warning (AEAD profiles only) | Lucky Thirteen (2013-02) |
| CL006 | no forward secrecy | error (`old`: info) | RFC 9325 §4.1 |
| CL007 | cipher-order preference against profile | info | Mozilla v5 change (2020-09) |
| CL008 | session tickets enabled | warning | RFC 9325 §4.3.3 |
| CL009 | weak DH parameters | error | CVE-2015-4000 (Logjam) |
| CL010 | weak or non-recommended curve | error / info | NIST SP 800-57 Part 1 Rev. 5 |
| CL011 | HSTS not configured | info | RFC 6797 |
| CL012 | HSTS max-age too short | warning | RFC 6797 §6.1.1 |
| CL013 | OCSP stapling against dated advice | info | see below |
| CL014 | unintelligible cipher token | info | ciphers(1ssl) |
| CL015 | cipher list selects nothing | error | ciphers(1ssl) |

Notes on behavior:

- **Implicit defaults are linted.** When a config never sets a protocol
  directive, cipherlint applies the server software's documented default and
  says so in the message. The important case is Apache: httpd's default
  `SSLProtocol all -SSLv3` keeps TLS 1.0/1.1 enabled, so an Apache vhost with
  no `SSLProtocol` line draws CL001 with the note `(SSLProtocol not set; …)`.
  Assumed defaults: nginx ≥ 1.23.4 (TLS 1.2–1.3), HAProxy ≥ 2.2
  (`ssl-min-ver TLSv1.2`), Caddy 2 (TLS 1.2–1.3).
- **Dead configuration is not a vulnerability.** On a TLS 1.3-only endpoint
  the TLS ≤ 1.2 cipher list cannot be negotiated, so CL004/005/006/015 are
  skipped there.
- **One finding per category.** A cipher list with six RC4 suites produces one
  CL004 RC4 finding naming them, not six findings.

## The dated policy tables

A profile is addressed as `name@date`. Editions currently shipped:

| Profile | Floor | Requires | Cipher policy | Stapling | Source |
|---|---|---|---|---|---|
| `modern@2023-10` | TLS 1.3 only | TLS 1.3 | n/a (1.3 suites fixed) | recommend on | Mozilla server-side TLS v5.7 |
| `intermediate@2023-10` | TLS 1.2 | TLS 1.3 enabled | FS + AEAD only | recommend on | Mozilla server-side TLS v5.7 |
| `old@2023-10` | TLS 1.0 (warned) | TLS 1.3 enabled | CBC tolerated, FS optional | recommend on | Mozilla server-side TLS v5.7 |
| `modern@2026-01` | TLS 1.3 only | TLS 1.3 | n/a | retired | this table |
| `intermediate@2026-01` | TLS 1.2 | TLS 1.3 enabled | FS + AEAD only | retired | this table |
| `old@2026-01` | TLS 1.0 (warned) | TLS 1.3 enabled | CBC tolerated, FS optional | retired | this table |

All editions share: server cipher preference **off** for modern/intermediate
and **on** for old (Mozilla flipped this in v5, 2020-09); session tickets
**off** for modern/intermediate; DH minimum **2048** bits (1024 for old,
which still draws CL009 below 1024); recommended curves **x25519,
secp256r1, secp384r1**; HSTS max-age **63072000** (two years).

### Why the 2026-01 edition retires the stapling recommendation

Every hardening guide of the 2010s said `ssl_stapling on`. Then Let's Encrypt
— the CA for the majority of the web's certificates — announced the end of
its OCSP service (shut down in 2025-08), and the CA/Browser Forum moved the
ecosystem toward short-lived certificates and CRLs. A stapling directive
pointed at a certificate with no OCSP responder does nothing. The 2026-01
tables therefore mark stapling **retired**: `ssl_stapling on` draws an info
finding under `…@2026-01`, while the same directive is exactly what
`…@2023-10` recommends. Pin the date you want to be held to.

This is the design argument for dated tables in general: advice changes, and
a linter that silently swaps its ruleset is indistinguishable from a flaky
one. cipherlint never edits a shipped edition — new advice lands as a new
date, and old dates keep resolving forever.
