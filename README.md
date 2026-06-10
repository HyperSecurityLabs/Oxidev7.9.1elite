# OxideCE-v7.7.7elite
<p align="center">
  <a href="https://www.kali.org/">
    <img src="https://www.kali.org/images/kali-dragon.svg" alt="Kali Linux" width="120"/>
  </a>
  <br>
  <img src="../logo-cp77-yellow-en@2x-a95c56ad.png" alt="OXIDE CE" width="380"/>
</p>

<h1 align="center" style="color: #557C93; font-family: 'Courier New', monospace;">
  OXIDE — Community Edition <span style="color:#b388ff;">v7.7.7-elite</span>
</h1>

<p align="center">
  <span style="color:#557C93; font-size: 1.1em;">
    Open eXtensible Intelligence & Detection Engine
  </span>
  <br>
  <span style="color:#00d4ff;">AI-Powered Security Toolkit</span>
  <span style="color:#557C93;"> · </span>
  <span style="color:#b388ff;">Red Team Operations</span>
  <span style="color:#557C93;"> · </span>
  <span style="color:#00e676;">Kali Linux Ready</span>
</p>

<br>

<p align="center">
  <a href="https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE">
    <img src="https://img.shields.io/badge/⛁_Repository-GitHub-557C93?style=for-the-badge&logo=github" alt="GitHub">
  </a>
  <a href="https://hypersecurityoffensivelabs-about.is-best.net/">
    <img src="https://img.shields.io/badge/⎈_Website-HyperSecurity-00d4ff?style=for-the-badge&logo=internetexplorer" alt="Website">
  </a>
  <a href="https://t.me/hypersecurity_offsec">
    <img src="https://img.shields.io/badge/✉_Telegram-@hypersecurity__offsec-b388ff?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>
  <br>
  <a href="https://www.kali.org/">
    <img src="https://img.shields.io/badge/⎈_Kali_Linux-Official_Tool-367bf0?style=for-the-badge&logo=kalilinux" alt="Kali Linux">
  </a>
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/⚙_Rust-2021_Edition-00e676?style=for-the-badge&logo=rust" alt="Rust">
  </a>
  <a href="https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues">
    <img src="https://img.shields.io/badge/⚠_Issues-Report-ff6b6b?style=for-the-badge&logo=github" alt="Issues">
  </a>
  <br>
  <a href="https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/discussions">
    <img src="https://img.shields.io/badge/💬_Discussions-Community-557C93?style=for-the-badge&logo=github" alt="Discussions">
  </a>
</p>

<br>

<p align="center">
  <b style="color:#00d4ff; font-size: 1.2em;">⭐ Support OXIDE for Kali Linux Official Repository</b>
  <br>
  <span style="color:#557C93;">
    If you find this tool useful in your security operations, please
    <a href="https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE" style="color:#b388ff; font-weight: bold;">star the repository on GitHub</a>.
    Your support helps us get OXIDE included in the official Kali Linux tools repository,
    making it accessible to the entire Kali community with a simple
    <code style="color:#00e676;">apt install oxide</code>.
  </span>
</p>

<br>

---

## 📋 Table of Contents

- [1. About OXIDE](#-1-about-oxide)
- [2. Kali Linux Integration](#-2-kali-linux-integration)
- [3. Installation](#-3-installation)
- [4. Quick Start](#-4-quick-start)
- [5. Module Reference](#-5-module-reference)
- [6. Zero-Day ML Engine](#-6-zero-day-ml-engine)
- [7. Report Formats](#-7-report-formats)
- [8. Configuration](#-8-configuration)
- [9. Changelog](#-9-changelog)
- [10. Build & Compilation](#-10-build--compilation)

---

## 🐉 1. About OXIDE

OXIDE is a modular security toolkit engineered for offensive operations. It integrates multiple detection techniques into a unified pipeline, from traditional vulnerability scanning to machine learning-based anomaly detection.

### Core Design

| Aspect | Detail |
|--------|--------|
| Language | Rust 2021 Edition — memory safe, zero-cost abstractions |
| Runtime | `tokio` async — non-blocking I/O, concurrent scanning |
| ML Stack | `smartcore` (Random Forest, SVM), `linfa` (clustering), `ndarray`, `statrs` |
| Target | Kali Linux primary, cross-platform compatible |
| Output | Auto-generated HTML (cyberpunk theme) + JSON reports |

### What Makes OXIDE Different

- **ML-Powered Anomaly Detection** — Statistical baselines + Random Forest classification catch what signature-based scanners miss
- **Automatic WAF Negotiation** — Detects and adapts to web protection layers during reconnaissance
- **Intelligent Payload Mutation** — AI-driven payload variation to evade detection systems
- **True Parallel Scanning** — Concurrent module execution with rate limiting
- **Graceful Operations** — Ctrl+C responsive, duration-respecting, per-request timeouts

---

## 🛡️ 2. Kali Linux Integration

OXIDE is built specifically with Kali Linux in mind. The toolkit integrates with the Kali ecosystem through:

### Native Features

```
├── Reconnaissance module ── Uses pnet (raw sockets) for active fingerprinting
│   └── src/recon.rs — Linux-only, compiled with #[cfg(target_os = "linux")]
│
├── Kali colour scheme ──── Truecolor output matching Kali brand
│   └── src/cli/display.rs — ELITE_KALI (85,124,148) primary palette
│
├── Cross-compilation ────── Built with Rust — runs on any Kali kernel
│
└── Package ready ────────── DEB packaging (oxide-ce-debian/) + Arch (PKGBUILD)
```

### Kali Tools Family

OXIDE complements existing Kali tools:

| Tool | OXIDE Equivalent | Integration |
|------|-----------------|-------------|
| `sqlmap` | SQLi scanner | ML-enhanced detection vs pure automation |
| `nmap` | Recon + fingerprinting | Application-layer focus |
| `burpsuite` | Fuzzing + payload mutation | CLI-native, scriptable |
| `metasploit` | Auto-exploit confirmation | Post-scan validation |

### Getting Into Kali Official Repos

OXIDE aims to join the official Kali Linux repository. To help:
- ⭐ **Star the repo**: [github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE)
- 🐛 **Report issues**: Help us stabilise through community feedback
- 📣 **Spread the word**: More visibility = faster inclusion

---

## 📦 3. Installation

### Kali Linux

```bash
# Prerequisites
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev cmake

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build OXIDE
git clone https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE.git
cd OxideCE-v7.7.7ELITE
cargo build --release

# Install system-wide
sudo cp target/release/oxide /usr/local/bin/
oxide --help
```

### Verify Installation

```bash
oxide --version        # → oxide 7.7.7-elite
oxide --list-modules   # → lists all 13 scanner modules
oxide --help           # → full usage
```

---

## 🚀 4. Quick Start

### Basic Scan

```bash
oxide --url https://example.com --modules all --duration 120
```

### Scan With Specific Modules

```bash
oxide --url https://example.com --modules sqli,xss,lfi,cmd-injection
```

### Zero-Day ML Scan

```bash
oxide --url https://example.com --zeroday --duration 120
```

### Multi-Target Scan

```bash
oxide --url https://target1.com --url https://target2.com --modules all
```

### Authenticated Scan

```bash
oxide --url https://example.com/admin --modules all --cookie "session=abc123"
```

### Proxy Routing

```bash
oxide --url https://example.com --proxy http://127.0.0.1:8080 --delay 200
```

### Output Specific Formats

```bash
oxide --url https://example.com --modules all --output html,json
```

---

## 🧩 5. Module Reference

### Scanner Modules

| Module | Flag | File | Detection Method |
|--------|------|------|------------------|
| SQL Injection | `sqli` | `src/scanner/sqli_scanner.rs` | Error-based, UNION, time-blind |
| Blind SQLi | `blind-sqli` | `src/scanner/blind_sqli_scanner.rs` | Time-based inference |
| Cross-Site Scripting | `xss` | `src/scanner/xss_scanner.rs` | Reflected, stored, DOM |
| Local File Inclusion | `lfi` | `src/scanner/lfi_scanner.rs` | Path traversal patterns |
| Path Traversal | `path-traversal` | `src/scanner/path_traversal_scanner.rs` | Directory escape sequences |
| Command Injection | `cmd-injection` | `src/scanner/cmd_injection_scanner.rs` | OS command injection |
| CORS | `cors` | `src/scanner/cors_scanner.rs` | Misconfiguration analysis |
| TLS Analysis | `tls` | `src/scanner/tls_scanner.rs` | Certificate + cipher audit |
| Default Credentials | `default-creds` | `src/scanner/default_creds_scanner.rs` | Known credential pairs |
| DB Fingerprinting | `db-fingerprint` | `src/scanner/db_fingerprinter.rs` | Banner + error analysis |
| Common App | `common-app` | `src/scanner/common_app_scanner.rs` | CMS + framework detection |

### Detection Modules

| Module | File | Purpose |
|--------|------|---------|
| Analyzer | `src/detection/analyzer.rs` | Core finding types and severity classification |
| Matcher | `src/detection/matcher.rs` | Pattern and signature matching engine |
| Signatures | `src/detection/signatures.rs` | Built-in vulnerability signatures |
| Scorer | `src/detection/scorer.rs` | Risk and severity scoring |
| Confirm | `src/detection/confirm.rs` | False-positive reduction and confirmation |
| Behavior | `src/detection/behavior.rs` | Behavioral analysis heuristics |
| Context | `src/detection/context.rs` | Reflection and context analysis |
| Timing | `src/detection/timing.rs` | Timing attack analysis |

### AI Modules

| Module | File | Purpose |
|--------|------|---------|
| Exploit Analyzer | `src/ai/exploit_analyzer.rs` | Post-exploit analysis |
| Response Analyzer | `src/ai/response_analyzer.rs` | Response pattern analysis |
| Payload Mutator | `src/ai/payload_mutator.rs` | AI-driven payload variation |
| Pattern Learner | `src/ai/pattern_learner.rs` | Adaptive pattern learning |

---

## 🧬 6. Zero-Day ML Engine

The zero-day module (`src/zero_day/`) is a self-contained ML anomaly detection system that runs independently of the signature-based scanners.

### Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌────────────┐
│  Phase 1    │ →  │  Phase 2     │ →  │  Phase 2.5  │ →  │  Phase 3   │
│  Crawl      │    │  ML Analysis │    │  Fuzz Test  │    │  Report    │
│  (30s max)  │    │  + Auto-    │    │  15 payload │    │  Success   │
│             │    │  Exploit    │    │  types      │    │  Rate      │
└─────────────┘    └──────────────┘    └─────────────┘    └────────────┘
```

### ML Technologies

| Component | Library | File |
|-----------|---------|------|
| Feature Extraction | Custom | `src/zero_day/features.rs` |
| Random Forest | `smartcore` | `src/zero_day/classifier.rs` |
| SVM Classifier | `smartcore` | `src/zero_day/classifier.rs` |
| Baseline Profiling | Statistical | `src/zero_day/baseline.rs` |
| Anomaly Scoring | Multi-signal | `src/zero_day/anomaly.rs` |
| Orchestration | Custom | `src/zero_day/engine.rs` |

### Features Extracted Per Response

Content length, response time, status code, header count, body entropy, special character density, path depth, query parameter count, JavaScript event handler presence, error pattern indicators, and response structure metrics.

### Auto-Exploit Confirmation

When the ML engine flags an anomaly, it automatically attempts confirmation:

| Detection | Payload Example |
|-----------|-----------------|
| SQL Injection | `' OR '1'='1` |
| XSS | `<img src=x onerror=alert(1)>` |
| LFI | `../../../../etc/passwd` |
| Command Injection | `; id` |
| SSTI | `{{7*7}}` |

---

## 📊 7. Report Formats

Reports auto-save to `reports/oxide_<timestamp>.<ext>` after every scan.

### HTML Report

```
File: reports/oxide_<timestamp>.html
Theme: Cyberpunk 2077 / Kali aesthetic
Features:
  - Google Fonts: Orbitron (headings), Rajdhani (body), Fira Code (URLs)
  - Scanline overlay and diagonal slash patterns
  - Animated gradient header with Kali colour scheme
  - Severity bars with glow effects
  - Custom scrollbar styling
  - Responsive layout
Code: src/report/html.rs
```

### JSON Report

```json
{
  "target_url": "https://example.com",
  "target_ip": "93.184.216.34",
  "duration_secs": 120,
  "discovered_urls": ["https://example.com/", "https://example.com/login"],
  "oxyde_version": "7.7.7-elite",
  "findings": [...]
}
```

### Other Formats

CSV (`src/report/csv.rs`) and XML (`src/report/xml.rs`) available.

---

## ⚙️ 8. Configuration

### Command-Line Flags

Defined in `src/cli/args.rs`:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | `String` | required | Target URL(s) |
| `--modules` | `String` | — | Comma-separated or `all` |
| `--duration` | `u64` | 300 | Scan duration limit (seconds) |
| `--output` | `String` | `html,json` | Report output formats |
| `--zeroday` | `bool` | false | Enable ML anomaly detection |
| `--list-modules` | `bool` | false | List available modules |
| `--insecure` | `bool` | false | Skip TLS verification |
| `--proxy` | `String` | — | HTTP proxy URL |
| `--cookie` | `String` | — | Session cookie |
| `--threads` | `u64` | 10 | Concurrent requests |
| `--delay` | `u64` | 0 | Inter-request delay (ms) |

### TOML Config File

```toml
# oxide-config.toml
[general]
threads = 10
delay_ms = 200
insecure = false

[proxy]
url = "http://127.0.0.1:8080"

[modules]
enabled = ["sqli", "xss", "lfi", "cmd-injection"]
```

---

## 📜 9. Changelog

### v7.7.7-elite (Current)

```
Added:
  ▪ Zero-Day ML detection engine — standalone anomaly scanning with auto-exploit
  ▪ Fuzz testing phase — 15 random payload types, crash/timeout/5xx tracking
  ▪ Cyberpunk 2077 HTML report theme — Orbitron/Rajdhani/Fira Code, scanlines,
    animated gradient header, severity glow effects
  ▪ Auto-save reports — both HTML and JSON written to reports/ directory
  ▪ WAF detection during reconnaissance — adaptive session negotiation
  ▪ Per-request timeout (10s) and per-exploit timeout (8s)
  ▪ Public get_discovered_urls() on HybridScanner

Changed:
  ▪ Banner gradient: Kali blue-grey → cyan → lavender
  ▪ Duration timer moved to exclude setup overhead
  ▪ --list-modules no longer requires --url
  ▪ Checkpoint format: red-line ━━━ OXIDE CHECKPOINT ━━━
  ▪ Author line: khaninkali [Kali-Linux]

Fixed:
  ▪ Ctrl+C responsiveness — polls shutdown flag every 200ms
  ▪ Vercel false positive — server-timing header removed from WAF detection
  ▪ WAF detection now runs during recon, not as separate post-crawl phase
  ▪ Duration limit enforced via per-request timeouts and should_continue() checks
  ▪ Set-Cookie parsing panic — &parts[1..] bounds guard
  ▪ TLS certificate parsing panic — short string bounds guard
  ▪ Session cookie parsing panic — parts[1..] bounds guard
  ▪ String slicing safety — filter.rs context extraction uses .get() with fallback
```

### v7.6.0

```
Initial Community Edition release.
Hybrid scanning pipeline with 13 scanner modules.
HTML, JSON, CSV, XML report output.
Plugin system and session hijacking detection.
```

---

## 🔧 10. Build & Compilation

### Release Build

```bash
cargo build --release
```

The release profile uses:
- `opt-level = 3` — maximum optimisation
- `lto = "fat"` — full link-time optimisation
- `strip = true` — stripped debug symbols
- `panic = "abort"` — minimal binary size

### Debug Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Workspace Structure

```
/                   # Main OXIDE package (binary + library)
├── src/            # Source code
├── oxide-proxy/     # Proxy sub-crate
├── hypersecurity/   # HyperSecurity sub-crate
├── oxide-ce-debian/ # Debian packaging
└── arch-pkg/        # Arch Linux packaging
```

### Debian Package Build

```bash
./build-ce-deb.sh
```

---

## 🤝 Contributing & Support

| Resource | Link | Purpose |
|----------|------|---------|
| GitHub | [HyperSecurityLabs/OxideCE-v7.7.7ELITE](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE) | Code, issues, roadmap |
| Website | [hypersecurityoffensivelabs-about.is-best.net](https://hypersecurityoffensivelabs-about.is-best.net/) | Project information |
| Telegram | [@hypersecurity_offsec](https://t.me/hypersecurity_offsec) | Community discussion |
| Issues | [GitHub Issues](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/issues) | Bug reports |
| Discussions | [GitHub Discussions](https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE/discussions) | Feature requests |

---

<p align="center">
  <br>
  <a href="https://www.kali.org/">
    <img src="https://www.kali.org/images/kali-dragon.svg" alt="Kali Linux" width="80"/>
  </a>
  <br><br>
  <b style="color:#00d4ff;">Built for Kali Linux · Targeting Official Repository Inclusion</b>
  <br><br>
  <a href="https://github.com/HyperSecurityLabs/OxideCE-v7.7.7ELITE">
    <img src="https://img.shields.io/badge/⭐_Star_on_GitHub-557C93?style=for-the-badge" alt="Star">
  </a>
  <br><br>
  <span style="color:#557C93;">
    <i>khaninkali | HyperSecurity Offensive Labs</i>
  </span>
</p>
