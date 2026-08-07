# Honeypot Threat Intelligence Report

**Generated:** 2026-08-06T15:56:53.862962+00:00
**Project:** PROJECT 5 - Honeypot Threat Intelligence Lab

## 1. Executive Summary

- Events analyzed: **66**
- Unique attacker IPs: **5**
- Sessions: **6**
- IPs listed on threat feeds: **4**
- Payloads analyzed: **5**
- Dominant attack type: **iot_botnet_propagation**

## 2. Methodology

- Honeypot: Cowrie (SSH/Telnet medium-interaction)
- SIEM: ELK Stack (Elasticsearch, Logstash, Kibana)
- Threat feeds: AbuseIPDB, AlienVault OTX, The Honeynet Project, lab_heuristic
- Reference: The Honeynet Project research practices

## 3. Attack Classification

| Attack Type | Count |
|---|---:|
| `iot_botnet_propagation` | 2 |
| `malware_download` | 1 |
| `manual_reconnaissance` | 1 |
| `cryptominer_deployment` | 1 |
| `credential_stuffing` | 1 |

### Automation vs Manual

| Mode | Count |
|---|---:|
| automated | 5 |
| likely_manual | 1 |

## 4. Notable Attackers

| IP | Sessions | Types | Feed Risk/Reputation |
|---|---:|---|---|
| `103.149.172.88` | 1 | iot_botnet_propagation | critical |
| `185.220.101.45` | 2 | iot_botnet_propagation, malware_download | critical |
| `198.51.100.77` | 1 | manual_reconnaissance | unlisted |
| `45.33.32.156` | 1 | cryptominer_deployment | high |
| `91.219.237.12` | 1 | credential_stuffing | high |

## 5. Payload Analysis

| File | Risk | Indicators | SHA256 |
|---|---|---|---|
| `a1b2c3d4e5f6-mirai.x86` | critical | filename_botnet_hint, iot_botnet | `b74f50eca27bf4688bea7eaf4af65f27cdca115c97fe55eb7414a3ab5cbe5b9b` |
| `b2c3d4e5f6a7-xmrig.tar.gz` | critical | cryptominer, filename_miner_hint | `b35687abbb2cb122cb568c2b1483f4983ba3cb6371d6bef23e5cc8ec349928de` |
| `c3d4e5f6a7b8-bot.arm7` | medium | filename_botnet_hint | `da078fa752a81fa9a81a0e720af708cc5bc257b0bad790858f256e5e38a3a602` |
| `c3d4e5f6a7b8-l.sh` | critical | background_exec, downloader, iot_botnet, make_executable, shell_script | `7c692b393a7039964f76b6fa08ebb4dd3fb2317d08b9238b8ca36e3454dd4247` |
| `f6a7b8c9d0e1-dropper.sh` | critical | background_exec, downloader, firewall_flush, log_wipe, make_executable, shell_script | `3922618aba8e14d807fa2b7a7d29b86a625d912567a851e665e9a2854a014c09` |

## 6. IOC Summary

- Attacker IPs: 5
- URLs: 6
- File hashes: 5
- Unique usernames tried: 12
- Unique passwords tried: 18

## 7. Timeline Stats

- Sessions: 6
- Global events: 66
- Attackers: 5

## 8. Defensive Recommendations

1. Disable password authentication for SSH; enforce key-based auth and fail2ban/crowdsec.
2. Never expose Telnet (TCP/23) on production systems; disable the service entirely.
3. Rate-limit new SSH connections at the edge firewall and block known bad ASN ranges.
4. Monitor outbound HTTP(S) from servers — unexpected wget/curl to unknown hosts is high-signal.
5. Alert on execution from /tmp, /var/tmp, and hidden filenames (e.g. /tmp/.x).
6. Keep an IOC watchlist from this lab and push to firewall / EDR deny lists.
7. Segment management interfaces onto a VPN or jump-host VLAN (Honeynet-aligned isolation).
8. Detect mining pools (stratum) and high sustained CPU; block mining pool domains.
9. Inventory IoT devices; change default credentials; block WAN access to device management ports.
10. Treat slow interactive SSH sessions after auth as potential hands-on-keyboard intrusions.
11. Block or geo-fence the 5 attacker IPs extracted in this run (validate against false positives first).

## 9. Deliverables Produced

- IOC database (`output/iocs/`)
- Attacker behavior report (this file + JSON)
- Attack timeline (`output/timelines/`)
- Defensive recommendations (section 8)
