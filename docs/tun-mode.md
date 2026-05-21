# TUN-mode (system-wide) VPN

The recommended way to route every app on your machine through the
tunnel — no SOCKS5 proxy config per-app, no browser-specific setup.

## Architecture

```
[every app]
     │ default route -> singrdp0 TUN
     ▼
[tun2socks.exe]            <- xjasonlyu/tun2socks (battle-tested external bin)
     │ SOCKS5 to 127.0.0.1:1080
     ▼
[sing-rdp-cli.exe]         <- our existing all-in-one
     │ VLESS + RDP wrap
     ▼
[your VPS:3389]
```

Two binaries chained together. `tun2socks` handles the OS-level TUN
device + routing; `sing-rdp-cli` handles the actual tunneling. A single
`.bat` starts both.

## Why two binaries and not one

I tried building a single Go binary (`sing-rdp-tun`) using
`github.com/sagernet/sing-tun`. That library has been in flux —
namespace renames (sagernet ↔ metacubex), internal compile errors at
specific tagged versions, breaking API shifts between minor releases.
Pinning to a coherent version isn't reliable.

`tun2socks` is much simpler scoped (one job: bridge TUN to SOCKS5), has
been stable for years, and is widely used by Clash, Mihomo, Karing, and
other VPN clients. Adopting it instead of writing our own is the
pragmatic call.

The Go source for `sing-rdp-tun` is still in the repo (`cmd/sing-rdp-tun/`)
in case sing-tun stabilizes upstream. For now `./deploy.sh build-clients`
doesn't build it.

## Deploy

### On the VPS

```bash
git pull
./deploy.sh build-clients
./deploy.sh fetch-tun2socks
ls -la ./dist/
```

You'll see:

```
sing-rdp-cli.exe                  # our SOCKS5 client
tun2socks-windows-amd64.exe       # OS TUN <-> SOCKS5 bridge
wintun.dll                        # Wintun driver shim (already there)
sing-rdp-vpn.bat                  # self-elevating launcher
sing-rdp-cli.bat                  # SOCKS5-only launcher (alternative)
```

Plus the macOS / Linux variants of `tun2socks-*`.

Now make the connection config:

```bash
PUBLIC_HOST=$(curl -s ifconfig.me) ./deploy.sh client-config --json > sing-rdp.json
```

(Note: use `--json` not `--json-tun` — tun2socks doesn't need our
TUN-specific config fields. Same simple `sing-rdp.json` works for both
the SOCKS5-only and the full-VPN modes.)

### Copy to Windows

```powershell
mkdir C:\sing-rdp
cd C:\sing-rdp

# scp each from the VPS:
scp user@vps:/root/vpnWrap/dist/sing-rdp-cli.exe .
scp user@vps:/root/vpnWrap/dist/tun2socks-windows-amd64.exe .
scp user@vps:/root/vpnWrap/dist/wintun.dll .
scp user@vps:/root/vpnWrap/dist/sing-rdp-vpn.bat .
scp user@vps:/root/vpnWrap/sing-rdp.json .
```

Five files in `C:\sing-rdp\`. Done.

### Run

**Double-click `sing-rdp-vpn.bat`.** UAC prompt → accept. A console
window opens showing:

```
Starting sing-rdp-cli (SOCKS5 on 127.0.0.1:1080)...
sing-rdp-cli 0.1.0
SOCKS5 listening on 127.0.0.1:1080
Starting tun2socks (TUN device + system route)...
INFO[0000] [STACK] tun://wintun
INFO[0000] [PROXY] socks5://127.0.0.1:1080
INFO[0000] [TUN] gateway routed
```

Every TCP connection from every app on your machine now goes through
the VPS. No per-app proxy config.

### Verify

```powershell
# Should print your VPS's IP, not your home IP — directly, without
# any --socks5 flag:
curl.exe https://api.ipify.org
```

### Stop

Close the console window or press **Ctrl+C** inside it. The TUN
interface and routes are torn down automatically. `sing-rdp-cli.exe`
is killed by the cleanup tail of the .bat.

## Caveats

### UDP

tun2socks supports UDP tunneling natively over SOCKS5. **But** sing-rdp-cli
(our SOCKS5 server) only forwards TCP — UDP packets from tun2socks will
be dropped. Consequences and workarounds same as before:

- DNS over UDP won't work. Use DoH in your browser, or set system DNS
  to a public DoT/DoH resolver.
- QUIC / HTTP/3 won't work; browsers fall back to TCP-based HTTP/2.
- Online games using UDP won't work.

Adding UDP support is a future TODO — it needs xudp (UDP over VLESS) on
both ends.

### Performance

Each new TCP connection spins up its own RDP+VLESS handshake (5–10
round trips before first byte). Real WireGuard is way faster. Mux on
the RDP layer is a future optimization.

### Process lifetime

If `sing-rdp-cli.exe` dies (crash, killed manually), `tun2socks.exe`
keeps running but every SOCKS5 dial fails — apps see "connection refused"
until you restart the .bat. Watchdog logic is on the TODO list.

### What about Linux / macOS?

The same model works — `tun2socks-linux-amd64` and `tun2socks-macos-*`
binaries are built by `./deploy.sh fetch-tun2socks`. Equivalent
launchers exist as shell scripts:

```bash
# On Linux/macOS, run as root or with sudo:
./sing-rdp-cli-linux-amd64 -c sing-rdp.json &
./tun2socks-linux-amd64 -device tun://singrdp0 -proxy socks5://127.0.0.1:1080
```

(Manual; I haven't shipped a packaged wrapper for Linux/macOS yet.)

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| UAC prompt loops | Windows policy blocks elevation — check Group Policy / antivirus |
| "wintun.dll missing" | Copy `wintun.dll` next to the .exe |
| tun2socks: "create interface failed" | Not running as admin; use the .bat |
| Apps don't route through VPN | Old route table cached; reboot or `route delete 0.0.0.0` and restart |
| sing-rdp-cli logs show connections, browser still loads from home IP | Browser cached the previous network state — close and reopen browser |
