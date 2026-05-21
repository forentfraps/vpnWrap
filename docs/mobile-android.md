# Android via Termux sidecar

Until a custom NekoBox/Hiddify build with the RDP transport ships (Path 3 in
the project root), Android's only route to the full RDP-camouflaged tunnel
is a two-process setup: `sing-rdp-client` running inside Termux, paired
with NekoBox doing the VLESS termination + system VPN.

Works. Not pretty. Battery hostile. But you keep the RDP wrap, which is
the whole point of this project.

## What you'll need

- Your already-deployed VPS (this repo, `./deploy.sh up` already done)
- An Android phone, **not Chinese vendor** (Xiaomi/Huawei/Oppo aggressively
  kill background processes — Termux will get murdered constantly). Pixel
  / Samsung / Sony work well.
- ~30 minutes of patience for first-time setup.

## One-time setup

### 1. On the VPS: cross-compile the client for Android

```bash
./deploy.sh build-mobile
ls dist/
# sing-rdp-client-android-arm64   (modern phones, last ~7 years)
# sing-rdp-client-android-armv7   (older devices)
```

To check your phone's CPU: in Termux later run `uname -m`. `aarch64` = arm64.

### 2. On the phone: install Termux + NekoBox

- **Termux**: install from [F-Droid](https://f-droid.org/en/packages/com.termux/)
  — *not* Google Play. The Play Store version is stuck on an old Android API
  and will fail silently on networking calls.
- **NekoBox**: Play Store or [GitHub releases](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases).

### 3. Get the binary onto the phone

Easiest: in Termux,

```bash
pkg update && pkg install openssh
# Then either:
scp user@vps-ip:/root/vpnWrap/dist/sing-rdp-client-android-arm64 ~/sing-rdp-client
# Or, if you'd rather avoid scp:
#   On VPS:   cd dist && python3 -m http.server 8080
#   In Termux: wget http://vps-ip:8080/sing-rdp-client-android-arm64 -O sing-rdp-client
#   (Open port 8080 temporarily on the VPS for this transfer only.)
chmod +x ~/sing-rdp-client
```

### 4. Get the client config

On the VPS:

```bash
./deploy.sh client-config
```

Note the `cookie`, `sni`, and `uuid` values from the output.

## Daily use

### 5. Start the RDP wrapper in Termux

```bash
~/sing-rdp-client \
    --local 127.0.0.1:1081 \
    --remote <VPS-IP>:3389 \
    --cookie <COOKIE-FROM-CLIENT-CONFIG> \
    --sni <SNI-FROM-CLIENT-CONFIG> \
    --hostname DESKTOP-MOBILE0 \
    --insecure
```

Leave this terminal open. If Termux goes background and gets killed, the
tunnel drops. See the **Keeping it alive** section below.

### 6. Configure NekoBox to use the local wrapper

In NekoBox:

- Tap **+** → **New Profile** → **VLESS**
- **Server address**: `127.0.0.1`
- **Server port**: `1081`
- **UUID**: paste the VLESS UUID from `client-config`
- **Security**: `none` (the outer RDP+TLS provides the privacy)
- **Network**: `tcp`
- Save → tap to connect → enable VPN service when Android prompts

NekoBox now routes the device's apps through the Termux sidecar through
your VPS.

## Keeping it alive

Android's Doze mode and per-vendor task killers will kill Termux within
minutes of going background, taking the tunnel with it.

### Termux:Wake

```bash
# In Termux:
termux-wake-lock
```

Adds an acquired wake-lock notification; survives Doze. Release with
`termux-wake-unlock` when you don't need the tunnel.

### Disable battery optimization

Android Settings → Apps → Termux → Battery → **Unrestricted**.
Repeat for NekoBox.

### Vendor-specific extras

- **Xiaomi / Redmi**: Settings → Battery → App battery saver → Termux & NekoBox → No restrictions. Also enable Autostart for both. This still doesn't fully fix it on MIUI — consider a different phone if you'll rely on this.
- **Samsung One UI**: Settings → Apps → Termux → Battery → Allow background activity + Optimize battery usage → Off for Termux.
- **Pixel / stock Android**: usually fine with just `termux-wake-lock`.

### Termux:Boot (auto-start on reboot)

Install [Termux:Boot](https://f-droid.org/en/packages/com.termux.boot/) from F-Droid, then:

```bash
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/start-sing-rdp <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
~/sing-rdp-client \
    --local 127.0.0.1:1081 \
    --remote VPS-IP:3389 \
    --cookie COOKIE \
    --sni SNI \
    --hostname DESKTOP-MOBILE0 \
    --insecure
EOF
chmod +x ~/.termux/boot/start-sing-rdp
```

Reboot to test. Future reboots will auto-start the tunnel.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Connection refused` in Termux | sing-rdp not running on VPS or firewall blocks 3389 — check `./deploy.sh status` |
| Termux dies after a few minutes | Doze/task killer; apply wake-lock + battery exemption |
| NekoBox connects but no traffic | Termux process died — check `ps` in Termux |
| `tls: handshake failure` in Termux | Cookie or SNI mismatch — re-fetch from `./deploy.sh client-config` |
| Phone reboot drops everything | Set up Termux:Boot as above |

## What this DOESN'T solve

- **iOS**: no equivalent, no path. iOS sandbox won't let any app host an
  external binary. The only iOS route is the custom-app build (Path 3).
- **Battery life**: expect noticeable hit. Mobile RDP-camouflage is not
  free.
- **Hostile networks** (captive portals, NATted carrier mobile data):
  Termux can't always reach the VPS at all. Test on Wi-Fi first.
