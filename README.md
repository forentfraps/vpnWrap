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

## Threat model

Target: TSPU-class DPI that fingerprints by protocol structure and active-probes
suspicious flows. Not designed to resist a state actor with endpoint compromise.

Specifically defends against:
- Port + protocol structure mismatch (we are byte-correct RDP through NLA)
- TLS ClientHello fingerprinting (we use utls to clone mstsc.exe's hello)
- Active probing (server presents a working RDP login screen; tunnel only opens on
  authenticated session with the right channel name)

Does **not** defend against:
- Volumetric anomaly (a single "RDP user" pushing 100 GB/day looks wrong — apply caps)
- Destination-IP heuristics (use business-grade hosting, not a fresh OVH box)
- Endpoint compromise / TLS interception on the device

## Layout

- `rdp/` — RDP protocol bits we need (X.224, RDPNEG, MCS framing, Fast-Path)
- `transport/` — sing-box `V2RayClientTransport` / `V2RayServerTransport` impls
- `shape/` — traffic shaper (server-dominant ratio + idle heartbeats)
- `cmd/sing-rdp-probe` — standalone tool for poking at an RDP endpoint to validate
  the handshake matches a real one
