# Honeypot Threat Intelligence Lab — Study Notes

## Goal

Collect real attacker behavior using honeypots and turn raw deception telemetry into actionable threat intelligence: IOCs, classifications, timelines, and defensive guidance.

## Stack mapping to The Honeynet Project ideas

| Practice | How this lab implements it |
|----------|----------------------------|
| Deception sensors | Cowrie SSH/Telnet honeypot |
| Rich interaction logging | Commands, downloads, auth attempts, client banners |
| Central analysis | ELK Stack (Logstash → Elasticsearch → Kibana) |
| Shared intel | Threat feed correlation (AbuseIPDB, OTX, offline Honeynet-tagged feed) |
| Controlled exposure | Non-standard mapped ports 2222/2223; isolated Docker network `honeynet_lab` |

## Attack classes detected by the analyzer

1. `ssh_bruteforce` — many failed logins then success  
2. `credential_stuffing` — high-volume failures, no shell  
3. `iot_botnet_propagation` — Mirai/busybox/arm binaries  
4. `cryptominer_deployment` — xmrig / mining pools  
5. `malware_download` — URL fetch into the honeypot FS  
6. `manual_reconnaissance` — slow interactive recon commands  
7. `defense_evasion` — iptables flush / log wipe  
8. `persistence` — crontab / startup hooks  
9. `telnet_abuse` — Telnet channel usage  

## Recommended live-lab workflow

1. Deploy Cowrie on a throwaway VPS or isolated VM.  
2. DNAT/firewall only 2222/2223 (or map 22→2222 carefully on a dedicated host).  
3. Wait for internet scanners (often minutes to hours).  
4. Ship `cowrie.json` into this analyzer (and/or Logstash).  
5. Publish IOCs and recommendations to your SOC playbooks.  

## Kibana quick checks (when ELK profile is up)

- Index pattern: `cowrie-*`  
- Visualize: top `attacker_ip`, `attack_stage`, `eventid`  
- Discover filter: `eventid: "cowrie.command.input"`  
