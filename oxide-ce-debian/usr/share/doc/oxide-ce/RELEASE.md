<p align="center">
  <img src="https://img.shields.io/badge/OXIDE%20v8.5.0community-edition-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/COMMUNITY%20EDITION-ff6450?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/COMMUNITY%20EDITION-beb0eb?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/plat-Linux%20%7C%20Win-aac3eb?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/Rust-2021-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white&labelColor=1a1a2e" />
</p>

<p align="center">
  <strong>OXIDE</strong> — next-gen AI-augmented web vulnerability scanner in Rust.<br/>
  SQLi · XSS · LFI · CMDi · Blind SQLi · Path Traversal · TLS Audit · ML Zero-Day<br/>
  <em>by HyperSecurityLabs</em>
</p>

<p align="center">
  <a href="https://github.com/hypersecuritylabs/OxideCE-v8.5.0community">
    <img src="https://img.shields.io/badge/%E2%AD%90%20Star%20on%20GitHub-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  </a>
  <a href="https://www.kali.org/tools/">
    <img src="https://img.shields.io/badge/Proudly%20crafted%20for-Kali%20Linux-557C94?style=for-the-badge&labelColor=1a1a2e&logo=kali-linux" />
  </a>
  <a href="https://hypersecuritylabs.netlify.app">
    <img src="https://img.shields.io/badge/HyperSecurityLabs-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  </a>
</p>

---

> **⚠️ WARNING**  
> OXIDE launches **real payloads** from a single binary — SQLi, destructive injections, concurrent fuzzing across all discovered vectors. It is designed for offensive operations and **will degrade or destroy unprotected targets**. False positives are inherent by design — always validate findings manually against a safe baseline.

---

### Key Features

| Area | Highlights |
|------|------------|
| **16+ Scanners** | SQLi, Blind SQLi, XSS (reflected/stored/DOM), LFI, CMDi, Path Traversal, CORS, TLS, Default Creds (6000+), Common Apps (2790+), DB Fingerprint, Session Hijack, Instagram OSINT |
| **AI / ML** | Random Forest + SVM zero-day anomaly detection, ngram pattern learner, genetic payload mutation |
| **Multi-Attack** | Concurrent scans across 3 targets, real-time `det:`/`err:` progress, duration enforcement |
| **Hypersecurity** | Kernel-level `.so` module — W+X memory scanning, cache sanitisation, memory barriers |
| **Output** | JSON / HTML / CSV / XML reports with evidence |
| **Hardening** | XOR-encrypted SQLite, proxy FFI sandbox, runtime enforcement |

### Destructive Capability

| Threat | Source | Impact |
|--------|--------|--------|
| Concurrent multi-vector fuzzing | `hybrid.rs:1312-1321` | SQLi+XSS+LFI+CMDi+NoSQL+SSTI + destructive SQL simultaneously |
| DROP TABLE / TRUNCATE | `sql_injection.rs:349-352` | Permanent data loss |
| Webshell deployment | `sql_injection.rs:324-332` | RCE via MySQL `INTO OUTFILE` |
| xp_cmdshell RCE | `sql_injection.rs:357-362` | Full Windows takeover |
| COPY TO PROGRAM RCE | `sql_injection.rs:378-381` | Reverse shell via PostgreSQL |
| Rate limit enforced | `worker.rs:147-151` | Capped at 1000 req/s, minimum 1ms delay floor |

### Quick Start

```bash
./oxide --url https://target.com --modules all
./oxide --url https://target.com --modules sqli,xss,lfi --output report.html --format html --duration 600
./oxide --url https://target1.com --url https://target2.com --multiattack --verbose
```

### Downloads & Checksums

| Package | Size | SHA256 |
|---|---|---|
| `oxide-ce_8.5.0community-edition_amd64.deb` | 3.1M | `5a6bc1dea5aa240af3db70010418576e9411b37f0a177eeb54dee24f7ce10fe5` |
| `oxide-ce-v8.5.0community-edition-linux.zip` | 4.2M | `6813a5e39675bf62ee6adf0dd3a319b1699243fc08a70ef217d92ce54447672d` |
| `oxide-ce-v8.5.0community-edition-windows.zip` | 4.1M | `ca59291c86e366cbd0f6ae3bdf5906c9025cd89cb48e08db86e9f1c45c692c23` |

**Linux contents:** `oxide` · `libhypersecurity.so` · `liboxide_proxy.so` · `oxide_tests.db` · `oxide_tests.db.enc` · `RELEASE.md` · `GITHUB.md` · `DISTRIBUTION.md`

**Windows contents:** `oxide.exe` · `hypersecurity.dll` · `oxide_proxy.dll` · `oxide_tests.db` · `oxide_tests.db.enc` · `RELEASE.md` · `WINDOWS.md` · `DISTRIBUTION.md`

### Verification

```sh
sha256sum oxide-ce_8.5.0community-edition_amd64.deb
sha256sum oxide-ce-v8.5.0community-edition-linux.zip
sha256sum oxide-ce-v8.5.0community-edition-windows.zip
```

### Installation

**Debian / Kali:**
```sh
sudo dpkg -i oxide-ce_8.5.0community-edition_amd64.deb
sudo apt install -f   # resolve dependencies
oxide-ce --url https://target.com
```

**Linux (portable):**
```sh
unzip oxide-ce-v8.5.0community-edition-linux.zip
cd oxide-v8.5.0community-edition-linux
./oxide --url https://target.com
```

**Windows:**
```powershell
unzip oxide-ce-v8.5.0community-edition-windows.zip
cd oxide-v8.5.0community-edition-windows
.\oxide.exe --url https://target.com
```

### Palette

```
OSAKA_JADE_B #50dca0 · LAVENDER #beb0eb · LAVENDER_BLUE #aac3eb
COL_CRIT #ff3232 · COL_HIGH #ff6450 · COL_MED #ffb432 · COL_DIM #788298
```

---

<p align="center">
  <a href="https://github.com/hypersecuritylabs/OxideCE-v8.5.0community">
    <img src="https://img.shields.io/badge/%E2%AD%90%20Star%20on%20GitHub-50dca0?style=for-the-badge&labelColor=1a1a2e" />
  </a>
  <a href="https://www.kali.org/tools/">
    <img src="https://img.shields.io/badge/Kali%20Linux-557C94?style=for-the-badge&labelColor=1a1a2e&logo=kali-linux" />
  </a>
</p>

<p align="center">
  <code>Built with 🦀 Rust · Forged in the offensive security trenches</code><br/>
  <strong>HyperSecurityLabs · OXIDE Framework v8.5.0community-edition</strong><br/>
  <a href="https://hypersecuritylabs.netlify.app">hypersecuritylabs.netlify.app</a>
</p>
