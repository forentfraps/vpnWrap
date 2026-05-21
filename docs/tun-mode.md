# sing-rdp-tun — system-wide TUN-mode VPN client

`sing-rdp-tun` is the "real VPN" version of the client. It creates a TUN
interface, sets your default route to it, and forwards every TCP
connection through the RDP+VLESS tunnel. No per-app proxy config needed —
every application running on your machine sees the tunnel transparently.

Compare to `sing-rdp-cli` (SOCKS5-only):

|                              | sing-rdp-cli | sing-rdp-tun |
|------------------------------|--------------|--------------|
| Setup complexity             | low          | medium       |
| Browser only                 | yes          | no           |
| All apps tunneled            | only if they support SOCKS5 | yes |
| Requires admin / root        | no           | yes          |
| Needs wintun.dll on Windows  | no           | yes          |
| Supports UDP                 | n/a          | not yet (TCP only) |

## Quick deploy

### On the VPS

```bash
git pull
./deploy.sh build-clients     # also fetches wintun.dll into ./dist/
ls ./dist/sing-rdp-tun*
ls ./dist/wintun.dll
PUBLIC_HOST=$(curl -s ifconfig.me) ./deploy.sh client-config --json-tun > sing-rdp-tun.json
```

You now have:

- `./dist/sing-rdp-tun.exe` (Windows) or platform variants
- `./dist/sing-rdp-tun.bat` (Windows self-elevating launcher)
- `./dist/wintun.dll` (Windows kernel driver shim)
- `./sing-rdp-tun.json` (config with auto-route enabled)

### Copy to Windows

```powershell
mkdir C:\sing-rdp-tun
cd C:\sing-rdp-tun
scp user@vps:/root/vpnWrap/dist/sing-rdp-tun.exe .
scp user@vps:/root/vpnWrap/dist/sing-rdp-tun.bat .
scp user@vps:/root/vpnWrap/dist/wintun.dll .
scp user@vps:/root/vpnWrap/sing-rdp-tun.json sing-rdp.json
```

`sing-rdp.json` and `sing-rdp-tun.json` use the same schema — rename
either one to whatever the .bat expects (`sing-rdp.json` by default).

### Run

Double-click `sing-rdp-tun.bat`. You'll see a UAC prompt — accept. A
console window opens showing:

```
sing-rdp-tun 0.1.0
tun:      singrdp0 172.19.0.1/30 mtu=1500
upstream: <vps>:3389 (cookie=user-XXXX sni=DESKTOP-XXXXXXX)
autoroute=true
stack started; routing all TCP through tunnel
apps should now reach the internet via <vps> — Ctrl+C to stop
```

That's it. Every TCP connection from every app on the machine now goes
through the tunnel.

### Verify

In a new PowerShell window:

```powershell
# Should print your VPS's public IP, not your home IP — directly,
# without any --proxy flag:
curl.exe https://api.ipify.org

# Browser test: open https://whatismyipaddress.com — same IP shown
```

## What you trade for system-wide routing

### UDP doesn't work (yet)

The VLESS protocol can carry UDP via the xudp extension but our implementation
is TCP-only right now. Consequences:

- **DNS over UDP (the default)** — won't work through the tunnel. There
  are three ways around this:
  1. Configure your system DNS to a public DoH or DoT resolver
     (1.1.1.1 / 8.8.8.8 over TCP). DNS-over-TCP works fine.
  2. Put `1.1.1.1` in Windows network adapter settings → IPv4 → Properties → DNS,
     then enable `DNS over HTTPS` (Windows 11) or use a DoH client.
  3. Use a browser with built-in DoH (Firefox, Brave) — DNS lookups for
     web traffic go through the browser's encrypted resolver and bypass the
     UDP issue entirely.
- **QUIC / HTTP/3 traffic** — most apps fall back to TCP automatically.
  Chrome opts back to HTTP/2 over TCP when QUIC fails.
- **Online games** — many use UDP. Don't expect them to work.

I'll add UDP support in a future iteration; it's a bigger lift because it
requires UDP-over-VLESS (xudp), which the inner sing-box VLESS would also
need to be configured for.

### Bypass for the VPS itself

`auto_route: true` would normally route ALL traffic into the TUN —
including the connection to the VPS, which would loop. sing-tun
automatically excludes the VPS's IP from the TUN routes so the underlying
RDP connection still uses your physical interface. You shouldn't need to
think about this, but if your VPS IP ever changes you may need to
restart the client.

### Performance

- One RDP+VLESS tunnel per TCP connection. That's expensive (each new
  connection does X.224 → TLS → CredSSP → VLESS handshake, ~5–10 RTTs).
  Browsing feels noticeably slower than a plain WireGuard VPN.
- Future optimization: multiplex connections inside a single long-lived
  RDP tunnel via VMess-style mux. Not yet implemented.

## Troubleshooting

### "wintun.dll missing"

You forgot to copy `wintun.dll` next to the .exe. It must be in the same
folder; Windows won't find it elsewhere by default.

### "create tun: failed to create wintun adapter"

You're not running as administrator. Use the `.bat` launcher which
self-elevates, or right-click the .exe → Run as administrator.

### "failed to set route" / no internet access after starting

Likely your Windows network drivers are interfering. Check:

1. The TUN interface exists: `ipconfig` should list a `singrdp0` interface
   with IP `172.19.0.1`.
2. Routes look right: `route print` should show `0.0.0.0/0` with gateway
   pointing to the TUN's address.

If not, the route install failed. Workaround: set `auto_route: false` in
the config and add the route manually:

```powershell
netsh interface ipv4 set address name="singrdp0" static 172.19.0.1 255.255.255.252
netsh interface ipv4 add route 0.0.0.0/0 "singrdp0" 172.19.0.1
# Plus exclude the VPS so the underlying tunnel doesn't loop:
netsh interface ipv4 add route <vps-ip>/32 "<your-normal-interface>" <your-normal-gw>
```

### Apps don't see the new route

Some apps cache the network state. Close and re-open the app after
starting sing-rdp-tun. Browsers especially.

### Speed is bad

Expected for now. See "Performance" above. The bottleneck is per-connection
handshake overhead. Mux is the fix; it's on the roadmap.

### How do I uninstall?

Close sing-rdp-tun (Ctrl+C in the console, or close the window). The TUN
interface and its routes disappear automatically. Delete the .exe / .dll
/ .bat / .json files to clean up.

Wintun's kernel driver self-uninstalls when no one is using it. Reboot
to clear any leftover state if you really want it gone.
