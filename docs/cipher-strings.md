# OpenSSL cipher-string evaluation in cipherlint

nginx (`ssl_ciphers`), Apache (`SSLCipherSuite`) and HAProxy (`ciphers`,
`ssl-default-bind-ciphers`) hand their cipher directive to OpenSSL verbatim.
To lint those directives without linking OpenSSL, cipherlint implements the
cipher-string mini-language (ciphers(1ssl)) against its own offline suite
table. This page documents exactly which subset is implemented, so you can
tell a real finding from a modeling gap.

## Semantics implemented

Tokens are separated by `:`, `,` or whitespace and evaluated left to right:

| Form | Meaning |
|---|---|
| `NAME` | Append matching suites (in table order) that are not already present and not killed. |
| `!NAME` | Remove matches and bar them from being re-added later. |
| `-NAME` | Remove matches; a later token may re-add them. |
| `+NAME` | Move already-selected matches to the end (lowest preference). |
| `A+B` (infix) | Intersection: suites matching every part, e.g. `ECDHE+AESGCM`. |
| `@STRENGTH` | Stable-sort the current list by symmetric key bits, strongest first. |

## Keywords implemented

`ALL`, `DEFAULT`, `COMPLEMENTOFDEFAULT`, `HIGH`, `MEDIUM`, `LOW`,
`EXPORT`/`EXP`, `eNULL`/`NULL`, `aNULL`, `RSA`/`kRSA`, `aRSA`,
`ECDSA`/`aECDSA`, `ECDHE`/`EECDH`/`kEECDH`/`kECDHE`, `DHE`/`EDH`/`kEDH`/`kDHE`,
`AES`, `AES128`, `AES256`, `AESGCM`, `CHACHA20`, `CAMELLIA`, `SEED`, `3DES`,
`DES`, `RC4`, `MD5`, `SHA`/`SHA1`, `SHA256`, `SHA384`, `TLSv1.2`, plus every
exact OpenSSL suite name in the table.

## Documented deviations from OpenSSL

1. **`DEFAULT` is approximated** as `ALL:!aNULL:!eNULL`. Real OpenSSL's
   DEFAULT also depends on build-time security level and version. For lint
   purposes the approximation is conservative: it never hides a weak suite
   that DEFAULT would enable.
2. **The universe is the curated table** (~50 suites that actually appear in
   server configs), not the full OpenSSL registry. A suite cipherlint does
   not know appears as a CL014 info finding rather than being silently
   dropped — the opposite of OpenSSL's behavior, and deliberately so: silent
   ignoring is how typos like `EECDH+AESGCM128` survive in production for
   years.
3. **TLS 1.3 suites are excluded from expansion.** OpenSSL ≥ 1.1.1 does not
   let cipher strings configure TLS 1.3; writing `TLS_AES_128_GCM_SHA256` in
   `ssl_ciphers` has no effect, and cipherlint reports exactly that instead
   of pretending it worked.
4. **`MEDIUM`/`LOW`/`HIGH` follow OpenSSL ≥ 1.1.0 grouping**: 3DES has its
   own keyword (`3DES`), RC4/SEED are `MEDIUM`, single DES is `LOW`.
5. **Security levels, `@SECLEVEL=` and cipher-suite aliases for PSK/SRP/GOST
   families are not modeled** — none of the four dialects' hardening guides
   use them. `@SECLEVEL` tokens surface as CL014.

## The dialect split

Caddy does not use OpenSSL cipher strings: its `ciphers` subdirective takes
standard (IANA) suite names, one per argument. cipherlint parses those
through the same table via the IANA column, so `TLS_RSA_WITH_AES_128_CBC_SHA`
in a Caddyfile and `AES128-SHA` in nginx.conf produce the same CL006 finding.
