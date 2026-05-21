!! VIBECODED - do not use in prod!!

# sing-rdp

RDP-DVC transport for sing-box. Wraps proxy traffic inside an RDP-shaped flow so it
matches DPI fingerprints for RDP (TCP/3389) and survives traffic-pattern analysis.

## Status

Early. Standalone mode (server pretends to be an RDP server) works for connectivity.
Embed mode (piggyback on a real xrdp/Windows RDP server via a Static Virtual Channel)
is the recommended deployment for production — see [docs/embed.md](docs/embed.md).

## Architecture

```
[VLESS client] -> [sing-rdp client transport] -> TCP/3389 -> [sing-rdp server] -> [VLESS server]
                       ^                                          ^
                       speaks X.224 + RDPNEG + TLS + CredSSP      validates NLA, opens VPNW SVC
                       opens "VPNW" SVC, frames data as           feeds bytes back to inbound
                       Fast-Path Output PDUs                      sing-box pipeline
```
