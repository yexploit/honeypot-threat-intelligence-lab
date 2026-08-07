# Getting Started in 3 commands

The fastest path from clone → first threat report.

## Windows

```powershell
git clone https://github.com/yexploit/honeypot-threat-intelligence-lab.git
cd honeypot-threat-intelligence-lab
.\scripts\setup.ps1
.\scripts\run_analysis.ps1
```

Then open:

1. [`output/reports/threat_report.md`](output/reports/threat_report.md)  
2. [`output/timelines/attack_timeline.md`](output/timelines/attack_timeline.md)  
3. [`output/iocs/ioc_database.csv`](output/iocs/ioc_database.csv)  

## Linux / macOS

```bash
git clone https://github.com/yexploit/honeypot-threat-intelligence-lab.git
cd honeypot-threat-intelligence-lab
chmod +x scripts/*.sh
./scripts/setup.sh
./scripts/run_analysis.sh
```

## Want the live honeypot next?

```powershell
.\scripts\start_lab.ps1 -Elk     # Windows: Cowrie + Kibana
```

```bash
./scripts/start_lab.sh --elk     # Linux: Cowrie + Kibana
```

Kibana → http://localhost:5601  
Full walkthrough → [README.md](README.md)
