<p align="center">
  <img src="assets/banner_intelligence.gif" alt="Honeypot Threat Intelligence Lab - live banner" width="560">
</p>

<p align="center">
  <a href="https://github.com/yexploit">
    <img src="https://img.shields.io/badge/author-@yexploit-7c3aed?style=flat-square&logo=github&logoColor=white" alt="author">
  </a>
  &nbsp;
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  &nbsp;
  <img src="https://img.shields.io/badge/Cowrie-Honeypot-06b6d4?style=flat-square" alt="Cowrie">
  &nbsp;
  <img src="https://img.shields.io/badge/ELK-Stack-005571?style=flat-square&logo=elastic&logoColor=white" alt="ELK">
  &nbsp;
  <img src="https://img.shields.io/badge/Feeds-OTX%20%7C%20AbuseIPDB-f59e0b?style=flat-square" alt="Threat Feeds">
  &nbsp;
  <img src="https://img.shields.io/badge/OS-Windows%20%7C%20Linux-22c55e?style=flat-square" alt="platform">
</p>

<br>

Turn attacker noise into **actionable threat intel**.  
This lab deploys a **Cowrie** honeypot, ships logs into the **ELK Stack**, correlates hits against **threat feeds**, and auto-builds **IOCs**, **timelines**, and a full **attacker behavior report** — so you spend minutes reviewing findings instead of hours stitching logs by hand.

> Educational / defensive research only · Sample payloads are **safe mocks** · Live honeypots belong on isolated lab hosts (ports `2222` / `2223`), never on production SSH/Telnet.

---

## What you get when you open this repo

| # | Deliverable | Where to look |
|---|-------------|----------------|
| 1 | **IOC database** | [`output/iocs/`](output/iocs/) |
| 2 | **Attacker behavior report** | [`output/reports/attacker_behavior_report.md`](output/reports/attacker_behavior_report.md) |
| 3 | **Attack timeline** | [`output/timelines/attack_timeline.md`](output/timelines/attack_timeline.md) |
| 4 | **Defensive recommendations** | [`output/reports/defensive_recommendations.json`](output/reports/defensive_recommendations.json) |

Already populated from realistic sample Cowrie traffic so you can explore results **before** deploying anything.

---

## Architecture

```text
                    Internet scanners / bots
                              |
                              v
                 +------------------------+
                 |  Cowrie honeypot       |
                 |  SSH :2222  Telnet:2223|
                 +-----------+------------+
                             |
              cowrie.json + downloads
                             |
              +--------------+--------------+
              |                             |
              v                             v
     +----------------+            +------------------+
     | Python analyzer|            | ELK Stack        |
     | classify/IOCs  |            | Logstash → ES   |
     | timeline/report|            | → Kibana UI      |
     +--------+-------+            +--------+---------+
              |                             |
              v                             v
     output/iocs|reports|timelines    Kibana dashboards
              |
              v
     Threat feeds (offline + AbuseIPDB / OTX)
```

Aligned with **The Honeynet Project** ideas: controlled deception, rich logging, and shared intelligence.

---

## Step-by-step guide

### Step 0 — Clone

```bash
git clone https://github.com/yexploit/honeypot-threat-intelligence-lab.git
cd honeypot-threat-intelligence-lab
```

### Step 1 — Install dependencies

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
.\scripts\setup.ps1
```
</details>

<details>
<summary><b>Linux / macOS</b></summary>

```bash
chmod +x scripts/*.sh
./scripts/setup.sh
```
</details>

This installs Python packages (`pyfiglet`, `colorama`) and creates `.env` from `.env.example`.

### Step 2 — Run the intel pipeline (no Docker needed)

Uses the included sample attacker sessions:

<details>
<summary><b>Windows</b></summary>

```powershell
.\scripts\run_analysis.ps1
```
</details>

<details>
<summary><b>Linux / macOS</b></summary>

```bash
./scripts/run_analysis.sh
```
</details>

Or from any OS:

```bash
python -m honeypot_lab
```

**What happens automatically**

1. Parse Cowrie JSON events  
2. Capture attacker IPs / sessions  
3. Log & score every command  
4. Analyze downloaded payloads  
5. Correlate IPs / URLs / hashes with threat feeds  
6. Classify attack types (botnet, miner, recon, …)  
7. Generate the IOC database  
8. Build the attack timeline  
9. Write the threat + behavior reports  

Open [`output/reports/threat_report.md`](output/reports/threat_report.md) when it finishes.

### Step 3 — (Optional) Deploy a live Cowrie honeypot

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows) or Docker Engine (Linux).

```powershell
# Windows — Cowrie only
.\scripts\start_lab.ps1

# Windows — Cowrie + full ELK
.\scripts\start_lab.ps1 -Elk
```

```bash
# Linux — Cowrie only
./scripts/start_lab.sh

# Linux — Cowrie + full ELK
./scripts/start_lab.sh --elk
```

| Service | URL / Port |
|---------|------------|
| Cowrie SSH | `localhost:2222` |
| Cowrie Telnet | `localhost:2223` |
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |

> Safety: ports map to **2222/2223**, not production 22/23. Only expose on a dedicated lab VM/VPS.

### Step 4 — Analyze live Cowrie logs

```bash
docker cp honeypot_cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ./data/live_cowrie.json
python -m honeypot_lab -f data/live_cowrie.json
```

### Step 5 — (Optional) Live threat-feed enrichment

```bash
# Linux / macOS
export ABUSEIPDB_API_KEY=your_key
export OTX_API_KEY=your_key
python -m honeypot_lab --live-feeds
```

```powershell
# Windows
$env:ABUSEIPDB_API_KEY="your_key"
$env:OTX_API_KEY="your_key"
python -m honeypot_lab --live-feeds
```

Without keys, the built-in offline feed in `data/threat_feeds/` still correlates sample IOCs.

### Step 6 — Stop the lab

```powershell
.\scripts\stop_lab.ps1
```
```bash
./scripts/stop_lab.sh
```

---

## Tools used

| Tool | Role in this lab |
|------|------------------|
| **Cowrie** | Medium/high-interaction SSH & Telnet honeypot — captures brute force + shell interaction |
| **ELK Stack** | Elasticsearch + Logstash + Kibana — search, analyze, visualize in real time |
| **Threat feeds** | AbuseIPDB, AlienVault OTX, Honeynet-tagged offline intel |
| **The Honeynet Project** | Research methodology reference |
| **Python analyzer** | Offline/online pipeline that produces every deliverable |

---

## Sample findings (already in `output/`)

| Attacker IP | Classification | Notes |
|-------------|----------------|-------|
| `185.220.101.45` | IoT botnet propagation | Mirai-style dropper + return visit |
| `45.33.32.156` | Cryptominer deployment | XMRig + mining pool persistence |
| `103.149.172.88` | Telnet IoT botnet | busybox loader + ARM bot |
| `198.51.100.77` | Manual reconnaissance | Interactive OpenSSH pacing |
| `91.219.237.12` | Credential stuffing | Auth spray, no shell |

Pipeline snapshot from the bundled sample: **66 events · 5 IPs · 6 sessions · 4/5 IPs feed-listed**.

---

## Repository map

```text
honeypot-threat-intelligence-lab/
├── README.md                 ← you are here
├── GETTING_STARTED.md        ← shortest path to first report
├── docs/methodology.md       ← Honeynet-aligned study notes
├── docker-compose.yml        ← Cowrie (+ optional ELK profile)
├── requirements.txt
├── .env.example
├── config/
│   ├── cowrie/               ← honeypot config
│   ├── logstash/pipeline/    ← Cowrie → Elasticsearch
│   └── kibana/               ← index pattern hints
├── data/
│   ├── sample_cowrie/        ← realistic attack sessions
│   ├── downloaded/           ← safe mock payloads
│   └── threat_feeds/         ← offline intel snapshot
├── honeypot_lab/             ← Python analysis package
├── output/                   ← generated IOCs / reports / timelines
└── scripts/                  ← setup · start · analyze · stop  (.ps1 + .sh)
```

---

## Project checklist (matches the original brief)

- [x] Deploy honeypot  
- [x] Expose controlled ports  
- [x] Capture attacker IPs  
- [x] Log commands  
- [x] Analyze payloads  
- [x] Correlate with threat feeds  
- [x] Classify attack types  
- [x] Generate indicators of compromise (IOC)  
- [x] Build attack timeline  
- [x] Create threat report  

---

## Enhancements beyond the brief

- Cross-platform scripts for **Windows and Linux**
- Offline-first demo (explore full reports with zero Docker)
- Automation vs manual attacker scoring
- Payload static analysis + SHA256 IOCs
- CSV IOC export for firewall / SIEM import
- Optional live AbuseIPDB + OTX API hooks

---

## Ethical use

For **defensive research and education** only.  
Do not reuse captured payloads or techniques offensively. Follow local law and institutional policy when exposing honeypots to the public internet.

---

<p align="center">
  <b>Honeypot Threat Intelligence Lab</b><br>
  Built by <a href="https://github.com/yexploit">yexploit</a>
</p>
