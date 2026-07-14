# cipherlint examples

Every file here is runnable against the built binary from the repository
root (`go build -o cipherlint ./cmd/cipherlint`).

| File | What it shows |
|---|---|
| `legacy-nginx.conf` | A 2014-vintage nginx config: TLS 1.0/1.1, RC4, 3DES, short HSTS. Exits 1 with errors. |
| `intermediate-nginx.conf` | A clean intermediate-profile nginx config. Exits 0. |
| `legacy-apache.conf` | The Apache default-protocol trap: no `SSLProtocol` line means TLS 1.0/1.1 are on. |
| `haproxy.cfg` | Global/bind merging: one hardened frontend, one that silently re-opens TLS 1.0. |
| `Caddyfile` | Caddy overrides that widen the protocol range and pin a CBC suite. |
| `ci-gate.sh` | A deploy gate: pinned profile date, `--fail-on warning`, Markdown output. |

Try the dated-table behavior on any of them:

```bash
./cipherlint lint -p intermediate@2023-10 examples/legacy-nginx.conf   # 2023 advice
./cipherlint lint -p intermediate@2026-01 examples/legacy-nginx.conf   # 2026 advice
```

The OCSP stapling finding flips between the two vintages — that is the point
of dating the tables.
