# Integrating sing-rdp into sing-box

sing-box does not yet have a fully stable runtime plugin API for V2Ray
transports. There are two practical paths.

## Option A — Patched sing-box build (recommended for now)

1. Vendor `github.com/vpnwrap/sing-rdp` into your sing-box fork.
2. In `transport/v2ray/registry.go` (path varies by version) find the switch
   on transport type:

   ```go
   switch transportOptions.Type {
   case C.V2RayTransportTypeHTTP:
       // ...
   case C.V2RayTransportTypeWebsocket:
       // ...
   ```

   Add:

   ```go
   case "rdp":
       return rdptransport.NewClientFromConfig(
           ctx, dialer, server, tlsOptions, transportOptions.Raw)
   ```

   …and the analogous case in the server-side registry.

3. Run `go build ./cmd/sing-box`. The resulting binary accepts
   `"transport": { "type": "rdp", ... }` in any VLESS / Trojan inbound/outbound.

## Option B — External daemon + loopback SOCKS

Keep sing-box unmodified. Run sing-rdp as a separate process exposing a
SOCKS5 listener; point sing-box's outbound at it.

```
client app -> sing-box (VLESS dialer) -> 127.0.0.1:1081 (sing-rdp client)
              ----> TCP/3389 with RDP wrapping ----> VPS:3389
                                                    -> sing-rdp server
                                                    -> 127.0.0.1:1234 (sing-box VLESS in)
```

This loses one layer of mux/keepalive efficiency but ships without patching.

## Client coverage

Because the transport is a V2Ray transport, any client that consumes a
sing-box / xray config will work once it links a build that includes the
patch above:

- **Android**: NekoBox for Android (sing-box backend), v2rayNG
- **iOS**: Streisand, Karing, Shadowrocket (via custom sing-box build —
  App Store builds use upstream sing-box, so the patched transport must be
  signed into the app; users on stock builds can use Option B with any
  SOCKS5 client)
- **Desktop**: v2rayN (Windows), Nekoray (cross-platform), Hiddify
- **Headless**: sing-box CLI

Path of least resistance for an open-source project: publish a fork of
Hiddify (which has the cleanest custom-transport story) with sing-rdp
baked in. Users get one APK / one .exe with no per-platform code.
