# Embed mode

In embed mode the sing-rdp server stands behind a real RDP server (xrdp on
Linux, Windows RDS, or Windows desktop with RDP enabled). The flow:

```
client --TCP/3389--> [edge] --post-NLA SVC traffic--> [real xrdp / Windows]
                       ^                                  ^
                       sing-rdp server inspects MCS       runs a normal session,
                       traffic, hijacks the "VPNW"        renders an idle desktop
                       static virtual channel             (cover traffic)
```

This is the configuration that survives **active probing**: TSPU connects
from a Russian IP and gets a real Windows login. The tunnel only exists on
authenticated sessions on a specific channel name.

## Why embed mode is worth the setup

| Capability                       | Standalone | Embed |
|----------------------------------|-----------:|------:|
| Byte-perfect X.224/RDPNEG        |  yes       |  yes  |
| TLS fingerprint matches mstsc    |  yes (uTLS)|  yes  |
| Passes CredSSP/NLA probing       |  no        |  yes  |
| Realistic screen-update traffic  |  shaped    |  real |
| Setup complexity                 |  low       |  high |

## Setup sketch (Linux server)

1. Install xrdp + a lightweight session (xrdp-Xorg, openbox, xterm).
2. Create a system user whose RDP session runs `/usr/local/bin/idle-cover`
   — a tiny script that opens a black 1920x1080 window and emits subtle
   updates on a timer (so the session has nonzero screen activity).
3. Build sing-box with sing-rdp patched in (see [integration.md](integration.md)).
4. Configure the inbound with `mode: embed` and embed.upstream =
   `127.0.0.1:3389`. The server tunnel logic intercepts the named SVC and
   leaves all other RDP traffic flowing untouched to xrdp.
5. Point your DNS at the VPS. Optionally hide behind a reverse proxy that
   ALPN-routes — though port 3389 alone is fine because real RDP is on
   the same port.

## Hardening notes

- Use a non-default RDP cookie that matches your corporate-looking story
  (e.g. `Cookie: mstshash=svc-jumpbox`).
- Enable Windows-style account lockout on the xrdp PAM stack so brute-force
  attempts hit a wall the same way a real server does.
- Don't expose the SVC name in any error path or banner. The whole point
  is that it's only present for authenticated, in-the-know clients.
