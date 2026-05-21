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
device + routing; `sing-rdp-cli` handles the actual tunneling. Just
double-click `sing-rdp-cli.exe` — it spawns `tun2socks` itself and
prompts UAC when needed.

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
sing-rdp-cli.exe                  # our all-in-one client (self-elevating, menu UI)
tun2socks-windows-amd64.exe       # OS TUN <-> SOCKS5 bridge
wintun.dll                        # Wintun driver shim
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
scp user@vps:/root/vpnWrap/sing-rdp.json .
```

Four files in `C:\sing-rdp\`. Done.

### Run

**Double-click `sing-rdp-cli.exe`.** A console window opens with an
interactive menu:

```
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║   sing-rdp-cli  ·  v0.1.0                                    ║
  ║   RDP-wrapped VLESS VPN client                               ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝

    Config
    server:       vps.example.com:3389
    sni:          DESKTOP-XYZ
    socks5:       127.0.0.1:1080
    admin:        no  (run as admin to enable TUN mode)

  What would you like to do?

    [1]  Start full VPN  (system-wide TUN) — will prompt for admin
    [2]  Start SOCKS5 proxy  (apps connect to 127.0.0.1:1080)
    [q]  Quit

  Choose [1]:
```

Hit Enter (or type `1`) → UAC prompt → accept. A new console opens
showing the live tunnel state. Every TCP/UDP connection from every app
on your machine now goes through the VPS — no per-app proxy config.

Power users can skip the menu by passing flags directly:

```powershell
sing-rdp-cli.exe -tun          # request UAC, run full VPN
sing-rdp-cli.exe               # interactive menu (default)
sing-rdp-cli.exe -no-menu      # SOCKS5 only, no menu (scriptable)
```

### Verify

```powershell
# Should print your VPS's IP, not your home IP — directly, without
# any --socks5 flag:
curl.exe https://api.ipify.org
```

### Stop

Close the console window or press **Ctrl+C** inside it. The TUN
interface and routes are torn down automatically, then `sing-rdp-cli`
exits — it kills its own `tun2socks` child as part of cleanup.

## Caveats

### UDP

UDP works end-to-end. `sing-rdp-cli` exposes a SOCKS5 UDP ASSOCIATE
relay and multiplexes outbound datagrams through the VLESS server using
`packetaddr` framing, so DNS, QUIC/HTTP3, and apps like Discord voice
all route through the tunnel.

### Performance

Each new TCP connection spins up its own RDP+VLESS handshake (5–10
round trips before first byte). Real WireGuard is way faster. Mux on
the RDP layer is a future optimization.

### Process lifetime

If `sing-rdp-cli.exe` dies (crash, killed manually), `tun2socks.exe`
keeps running but every SOCKS5 dial fails — apps see "connection refused"
until you restart `sing-rdp-cli.exe`. Watchdog logic is on the TODO list.

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
| tun2socks: "create interface failed" | Not running as admin; pick option [1] from the menu (UAC) instead of [2] |
| Apps don't route through VPN | Old route table cached; reboot or `route delete 0.0.0.0` and restart |
| sing-rdp-cli logs show connections, browser still loads from home IP | Browser cached the previous network state — close and reopen browser |
