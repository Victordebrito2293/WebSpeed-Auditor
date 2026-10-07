# WebSpeed Auditor

**Local**, **offline**, and **privacy-first** website performance and best-practices audit. A 100% open-source Rust tool with no accounts, no API keys, no telemetry — nothing is sent to third parties except the HTTP requests made **to the site you are auditing**.

```
webspeed-auditor https://example.com
```

## Why

Performance audit tools usually send your URL to a cloud server, require sign-up, or run third-party code in a browser. WebSpeed Auditor runs **on your machine**, reads only what the site itself publishes, and produces a report answering five questions:

1. **What was tested and what was the result?**
2. **What problems exist** — with severity, evidence, impact, and how to fix them?
3. **What is already optimized?**
4. **What could not be tested in this environment** (and why)?
5. **What is the overall score?**

## Installation

### Build from source (recommended)

Requires: [Rust 1.88+](https://rustup.rs) (2024 edition).

```bash
git clone https://github.com/webspeed-auditor/webspeed-auditor.git
cd webspeed-auditor
cargo build --release
./target/release/webspeed-auditor --help
```

### Pre-built binaries

The release workflow produces signed artifact binaries for Linux (x86_64/aarch64), macOS (x86_64/aarch64), and Windows (x86_64) on the GitHub releases page.

## Usage

```bash
# Terminal report (default)
webspeed-auditor https://example.com

# JSON for CI/CD
webspeed-auditor https://example.com --format json --output report.json

# Self-contained HTML (no scripts, no external resources)
webspeed-auditor https://example.com --format html --output report.html

# Home page only, more verbose
webspeed-auditor https://example.com --no-crawl --verbose

# Silent mode (only final report)
webspeed-auditor https://example.com --quiet --format json
```

Without a URL, the tool shows a banner and asks for the URL interactively.

### Options

| Option | Default | Description |
|---|---|---|
| `--max-pages <N>` | 5 | Max pages in crawl (1–50; 1 = home only) |
| `--timeout <S>` | 15 | Timeout per network operation, seconds (1–120) |
| `--concurrency <N>` | 4 | Concurrent requests (1–16) |
| `--output <FILE>` | — | Write report to file (nothing written without this) |
| `--format <FMT>` | terminal | `terminal`, `json`, or `html` |
| `--no-crawl` | — | Do not follow internal links |
| `--quiet` | — | No progress logs (only final report) |
| `--verbose` | — | Verbose progress and every request (stderr) |

Report goes to **stdout**, progress to **stderr** — safe for pipelines:

```bash
webspeed-auditor https://example.com --format json --quiet > report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Audit completed (report generated even with partial failures) |
| 1 | Failed to generate/write report |
| 2 | Invalid input or URL rejected by security |

## What is checked

- **Network**: DNS resolution, IPv4/IPv6 addresses, TLS handshake, certificate validity and expiry, redirect chain, protocol version (HTTP/1.1, HTTP/2), TTFB.
- **Performance**: total page weight, document size, TTFB.
- **HTML**: structure, links (internal/external), iframes, viewport `<meta>`, distinct external origins, document size, content-type compatibility.
- **CSS**: total and inline volume, duplicate stylesheets, excessive inline CSS, failed stylesheet recovery.
- **JavaScript**: volume, blocking vs `defer`/`async`/`module`, duplicate scripts, individual file sizes.
- **Images**: legacy vs modern formats (WebP/AVIF), images above size threshold, `srcset`/`sizes`.
- **Fonts**: external and inline font volume, external font preload.
- **Caching**: `Cache-Control`, `ETag`/`Last-Modified`, `immutable` on HTML.
- **Compression**: gzip/brotli/deflate per resource type, `Vary` header.
- **Best Practices**: security headers (HSTS, `X-Content-Type-Options`), cookies (`Set-Cookie` only counted — values never collected), declared vs actual Content-Type (sniffing), HTTPS, redirects and redirect chain.

Full thresholds: [`docs/SCORING.md`](docs/SCORING.md).

## Privacy

- **No data persisted**: the entire audit lives in memory during execution and is discarded at the end.
- **No files created without `--output`**, and nothing is written automatically.
- **No telemetry, no analytics, no crash reports, no auto-updater, no accounts, no API keys.**
- The only external traffic is the requests **to the audited site** (and the DNS needed to resolve it). No data is sent to third parties.
- The report contains only target-site data — never local operator data (paths, user, environment).
- Set-Cookie: only the **count** is reported; values are never read, stored, or logged.
- The User-Agent identifies the tool and project, never the operator.

Details: [`docs/SECURITY.md`](docs/SECURITY.md) and [`SECURITY.md`](SECURITY.md).

## Security

- **SSRF (Server-Side Request Forgery)**: every URL is validated before each request — including **at every redirect hop** and **at every DNS resolution** (defense against DNS rebinding). Loopback, private networks, link-local, cloud metadata (169.254.169.254 etc.), CGNAT, reserved addresses, and NAT64/6to4/Teredo translations are blocked.
- **No CLI flag to disable SSRF protection.** It can only be disabled by code in local tests.
- Absolute limits: 10 MiB per body, 60 subresources, 10 redirects, URL max 2048 chars, concurrency 1–16, timeout 1–120 s.
- Remote content is treated as **never trusted**: malformed HTML cannot panic, HTML report escapes all dynamic content, and the report is self-contained (no `<script>`, no external resources).
- `unsafe` is **forbidden** throughout the codebase (`#![forbid(unsafe_code)]`).

## How the score works

Each category starts at 100. Findings deduct fixed, documented amounts (Critical −30, High −15, Medium −8, Low −3, Info 0). The weighted average is computed **only over categories actually measured** — unmeasured categories never inflate the score. If nothing could be measured, the score is 0 and the report explicitly states it does not evaluate the site.

Full formula, weights, and thresholds: [`docs/SCORING.md`](docs/SCORING.md).

## Honest limitations

This tool does not do magic and declares what it does **not** measure:

- **Core Web Vitals (LCP/CLS/INP)**: no real browser — measurement is static HTTP.
- **HTTP/3 (QUIC)**: not probed (avoids problematic dependencies).
- **JavaScript is not executed**: JS-rendered pages have partial analysis.
- **DNS records (CNAME)**: not collected; only resolution and IPs.
- **Accessibility**: only performance-linked aspects (image dimensions, lazy loading).
- **Measurement environment**: times vary with network, CDN, and target load.

All limitations appear in the "Not tested" section of every report.

## Development

```bash
cargo test          # 135+ tests (unit + integration + SSRF)
cargo fmt --check
cargo clippy --all-targets
```

- Full usage: [`docs/USAGE.md`](docs/USAGE.md)
- Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Build and releases: [`docs/BUILD.md`](docs/BUILD.md)

## License

[MIT](LICENSE).
