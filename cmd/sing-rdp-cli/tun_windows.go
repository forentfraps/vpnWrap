//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Windows TUN-mode orchestration. Goal: turn sing-rdp-cli into a
// system-wide VPN by:
//
//   1. Resolving the VPS host from config -> IPv4.
//   2. Pinning that IPv4 to the *current* default gateway via a /32 host
//      route — if we don't, our default-route-via-wintun will catch the
//      underlying RDP tunnel itself and loop forever.
//   3. Spawning tun2socks.exe (found alongside our binary) so it creates
//      a Wintun adapter and forwards every TUN packet through our local
//      SOCKS5 listener.
//   4. Configuring the Wintun adapter (IP + default route, low metric).
//   5. Watching for shutdown signals, then tearing all of it back down.
//
// All "routing" operations are shell-outs to `route` / `netsh`. That's
// uglier than Windows API calls via golang.org/x/sys/windows, but it's
// considerably less code, the commands are stable for ~25 years, and it
// matches the path most VPN docs describe so users can debug what we did.

const (
	tunAlias      = "wintun"
	tunAddress    = "198.18.0.1"
	tunPrefix     = 15      // matches the standard tun2socks fake subnet
	tunDefaultMet = 5
	tunIfaceMet   = 1       // Wintun's interface metric — must be low so
	                        // its default-route candidate wins over physical NICs
	tunHostMet    = 1
	tun2socksExe  = "tun2socks-windows-amd64.exe"
)

// runTUN brings the VPN up, blocks until ctx is cancelled, then tears
// down. Called from main when -tun is passed.
//
// On any failure during setup we run whatever cleanup has been registered
// so far and return — partial state is the worst outcome.
func runTUN(ctx context.Context, cfg *Config) error {
	// Resolve VPS host -> IPv4.
	vpsHost, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		return fmt.Errorf("parse server %q: %w", cfg.Server, err)
	}
	vpsIP, err := resolveIPv4(vpsHost)
	if err != nil {
		return fmt.Errorf("resolve VPS %q: %w", vpsHost, err)
	}
	log.Printf("[tun] VPS = %s (%s)", vpsHost, vpsIP)

	// Snapshot the original default gateway BEFORE we install our route.
	gw, err := getDefaultGateway()
	if err != nil {
		return fmt.Errorf("read default gateway: %w", err)
	}
	log.Printf("[tun] original default gateway: %s", gw)

	var cleanup cleanupStack
	defer cleanup.Run()

	// Locate tun2socks.exe next to our own binary. We ship it via
	// `./deploy.sh build-clients` into the same dist/ folder users
	// extract from.
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	tun2socksPath := filepath.Join(filepath.Dir(exePath), tun2socksExe)
	if _, err := os.Stat(tun2socksPath); err != nil {
		return fmt.Errorf("tun2socks not found at %s "+
			"(expected next to sing-rdp-cli.exe — run ./deploy.sh build-clients): %w",
			tun2socksPath, err)
	}

	// --- 1. Pin VPS to the original gateway ---------------------------
	log.Printf("[tun] adding host route %s/32 via %s", vpsIP, gw)
	if err := addHostRoute(vpsIP, gw, tunHostMet); err != nil {
		// Often "object already exists" — log and continue.
		log.Printf("[tun] (host route note: %v)", err)
	}
	cleanup.Add(func() error {
		log.Printf("[tun] removing host route %s/32", vpsIP)
		return removeHostRoute(vpsIP)
	})

	// --- 2. Spawn tun2socks -------------------------------------------
	// tun2socks uses logrus; valid levels are trace/debug/info/warning/
	// error/fatal/panic. The intuitive "warn" is REJECTED with a fatal
	// at startup ("not a valid logrus Level"), so always use "warning"
	// or "info". We go with "info" because tun2socks's per-packet
	// chatter is gated behind debug and the info lines are useful
	// startup confirmation.
	tun2socksCmd := exec.CommandContext(ctx, tun2socksPath,
		"-device", tunAlias,
		"-proxy", fmt.Sprintf("socks5://%s", cfg.LocalSOCKS),
		"-loglevel", "info",
	)
	tun2socksCmd.Stdout = os.Stdout
	tun2socksCmd.Stderr = os.Stderr
	log.Printf("[tun] starting tun2socks: %s", filepath.Base(tun2socksPath))
	if err := tun2socksCmd.Start(); err != nil {
		return fmt.Errorf("start tun2socks: %w", err)
	}
	tun2socksExited := make(chan struct{})
	go func() {
		_ = tun2socksCmd.Wait()
		close(tun2socksExited)
	}()
	cleanup.Add(func() error {
		if tun2socksCmd.Process != nil {
			_ = tun2socksCmd.Process.Kill()
		}
		return nil
	})

	// --- 3. Wait for Wintun adapter to appear -------------------------
	// Race-aware wait: if tun2socks itself dies before the adapter
	// shows up, surface that immediately rather than blocking on the
	// timeout. The earlier version waited the full 10s even when the
	// real failure (logrus level rejection) had been visible since t+0.
	if err := waitForAdapterOrExit(tunAlias, tun2socksExited, 10*time.Second); err != nil {
		return err
	}

	// --- 4. Configure Wintun (IP + interface metric + default route) ---
	tunIface, err := net.InterfaceByName(tunAlias)
	if err != nil {
		return fmt.Errorf("look up %s interface index: %w", tunAlias, err)
	}
	tunIfIndex := tunIface.Index
	log.Printf("[tun] %s is interface index %d", tunAlias, tunIfIndex)

	// `netsh ... set address` is a no-op on a freshly-created Wintun
	// adapter (it has no IPv4 config to "set"). Use `add address`
	// which works regardless of starting state.
	log.Printf("[tun] adding IP %s/%d to %s", tunAddress, tunPrefix, tunAlias)
	if err := addInterfaceIP(tunAlias, tunAddress, prefixToNetmask(tunPrefix)); err != nil {
		return fmt.Errorf("add %s ip: %w", tunAlias, err)
	}
	cleanup.Add(func() error {
		// The adapter goes away when tun2socks dies, taking the IP
		// with it. Best-effort delete in case we're re-launched and
		// the IP is somehow sticky.
		return runQuiet("netsh", "interface", "ipv4", "delete", "address",
			"name="+tunAlias, "address="+tunAddress)
	})

	// Force Wintun's interface metric low so its default route wins
	// against the physical NIC's. Setting this disables
	// AutomaticMetric (confirmed by user's Get-NetIPInterface output:
	// "AutomaticMetric: Disabled, InterfaceMetric: 1").
	log.Printf("[tun] lowering %s interface metric to %d", tunAlias, tunIfaceMet)
	if err := setInterfaceMetric(tunAlias, tunIfaceMet); err != nil {
		return fmt.Errorf("set %s interface metric: %w", tunAlias, err)
	}

	// `route add` without `IF <index>` lets Windows infer the
	// interface from the next-hop. If the next-hop isn't directly
	// reachable on any adapter (which happens when bug #1 above bit
	// us, but also as a transient during startup), Windows binds the
	// route to the WRONG interface — typically Ethernet. The route
	// then takes Ethernet's interface metric, which buries it below
	// the physical default route.
	//
	// Pinning the route to Wintun's interface index makes the route
	// inherit Wintun's interface metric (1), giving an effective
	// metric of 1+5=6 vs Ethernet's 0+50=50. Ours wins.
	log.Printf("[tun] installing default route via %s (metric %d, if %d)", tunAddress, tunDefaultMet, tunIfIndex)
	if err := addDefaultRouteOnIface(tunAddress, tunDefaultMet, tunIfIndex); err != nil {
		return fmt.Errorf("install default route: %w", err)
	}
	cleanup.Add(func() error {
		log.Printf("[tun] removing default route via %s", tunAddress)
		return removeDefaultRoute(tunAddress)
	})

	// --- 4b. Diagnostic: dump the chosen default route -----------------
	// Tells the user *and* future-me-debugging which route the OS
	// actually picked, so we don't have to guess from inside out.
	if chosen, err := chosenDefaultRoute(); err == nil {
		log.Printf("[tun] OS default route is now: %s", chosen)
		if !strings.Contains(chosen, tunAddress) {
			log.Printf("[tun] WARNING: default route is NOT our Wintun gateway (%s). " +
				"Traffic may still leak through the physical interface — check " +
				"interface metrics with `Get-NetIPInterface | Where InterfaceAlias -eq wintun`",
				tunAddress)
		}
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Printf("  VPN is UP. All traffic now routes through %s\n", vpsHost)
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println("============================================================")
	fmt.Println()

	// --- 5. Supervise --------------------------------------------------
	select {
	case <-ctx.Done():
		log.Printf("[tun] shutdown signal received")
	case <-tun2socksExited:
		log.Printf("[tun] tun2socks exited unexpectedly — shutting down")
	}
	return nil
}

// resolveIPv4 returns the first IPv4 address for host, or an error if
// none is available. We don't tunnel IPv6 right now, so picking IPv4 is
// the right choice.
func resolveIPv4(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
		return "", fmt.Errorf("host %q is IPv6; not supported", host)
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ip4 := a.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return "", errors.New("no IPv4 address found")
}

// getDefaultGateway runs `route print -4 0.0.0.0` and extracts the
// gateway of the lowest-metric default route.
//
// Sample output:
//
//   IPv4 Route Table
//   ===========================================================
//   Active Routes:
//   Network Destination     Netmask          Gateway         Interface  Metric
//             0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.42      25
//   ...
//
// We pick the first matching default route. If the system has multiple,
// Windows itself would also use the lowest-metric one — and `route print`
// orders by metric, so first-match is correct.
func getDefaultGateway() (string, error) {
	out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := fields[2]
			// Skip our own default route if it's already installed
			// (idempotent restart).
			if gw == tunAddress {
				continue
			}
			if net.ParseIP(gw) == nil {
				continue
			}
			return gw, nil
		}
	}
	return "", errors.New("no IPv4 default route found")
}

func addHostRoute(dst, gw string, metric int) error {
	return runQuiet("route", "add", dst, "mask", "255.255.255.255",
		gw, "metric", fmt.Sprint(metric))
}

func removeHostRoute(dst string) error {
	return runQuiet("route", "delete", dst, "mask", "255.255.255.255")
}

func removeDefaultRoute(via string) error {
	// `route delete 0.0.0.0` would clobber the original default route
	// too; specifying the gateway scopes the delete to ours.
	return runQuiet("route", "delete", "0.0.0.0", "mask", "0.0.0.0", via)
}

// addInterfaceIP assigns an IPv4 address to the given adapter using
// `netsh ... add address`. This is the correct verb for a freshly
// created adapter that has no existing IPv4 config — `set address`
// silently no-ops in that state because there's nothing to "set".
func addInterfaceIP(alias, ip, mask string) error {
	return runQuiet("netsh", "interface", "ipv4", "add", "address",
		"name="+alias, "address="+ip, "mask="+mask)
}

// addDefaultRouteOnIface adds 0.0.0.0/0 explicitly bound to a specific
// interface index. Without `IF <index>`, Windows picks an interface
// based on next-hop reachability, which can end up wrong during the
// brief window when Wintun's IP isn't fully propagated yet (and stays
// wrong even after).
func addDefaultRouteOnIface(via string, metric, ifIndex int) error {
	return runQuiet("route", "add", "0.0.0.0", "mask", "0.0.0.0",
		via, "metric", fmt.Sprint(metric), "IF", fmt.Sprint(ifIndex))
}

// setInterfaceMetric overrides the OS-chosen interface metric on the
// given adapter. We use this to force Wintun's effective default-route
// metric below the physical NIC's, otherwise Windows ignores our default
// route entirely.
func setInterfaceMetric(alias string, metric int) error {
	return runQuiet("netsh", "interface", "ipv4", "set", "interface",
		alias, fmt.Sprintf("metric=%d", metric))
}

// chosenDefaultRoute returns a short string describing the default route
// the OS is *currently* using (the lowest-effective-metric 0.0.0.0/0
// entry). Used as a post-install diagnostic — if our installation
// didn't actually become THE default route, we want to say so loudly
// instead of pretending the VPN is up.
//
// Format: "gateway=X.X.X.X iface=Y.Y.Y.Y metric=N"
func chosenDefaultRoute() (string, error) {
	out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output()
	if err != nil {
		return "", err
	}
	var best []string
	bestMet := 1 << 30
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		var met int
		if _, err := fmt.Sscanf(fields[4], "%d", &met); err != nil {
			continue
		}
		if met < bestMet {
			bestMet = met
			best = fields
		}
	}
	if best == nil {
		return "", errors.New("no default route in table")
	}
	return fmt.Sprintf("gateway=%s iface=%s metric=%d", best[2], best[3], bestMet), nil
}

// runQuiet executes name+args, capturing output only when the command fails
// (so the user's console isn't drowned in netsh chatter on success).
func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitForAdapterOrExit polls for a network interface by name AND watches
// for tun2socks dying. Returns nil when the adapter appears, or an error
// describing why we gave up (timeout OR tun2socks exited early).
//
// The early-exit path matters because tun2socks's startup errors —
// invalid loglevel, missing wintun.dll, port conflicts — surface on its
// stderr the instant it's killed by `log.Fatal`. Without this check, the
// orchestrator just waits the full timeout and reports "adapter never
// appeared" while the actual cause scrolled past 10 seconds ago.
func waitForAdapterOrExit(name string, exited <-chan struct{}, timeout time.Duration) error {
	deadline := time.After(timeout)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if adapterExists(name) {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("tun2socks exited before adapter %q came up (check the fatal/error line above)", name)
		case <-deadline:
			return fmt.Errorf("adapter %q not found within %s", name, timeout)
		case <-tick.C:
			// loop and re-poll
		}
	}
}

func adapterExists(name string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifa := range ifaces {
		if strings.EqualFold(ifa.Name, name) {
			return true
		}
	}
	return false
}

// prefixToNetmask converts a CIDR prefix length into the dotted-quad
// netmask `netsh` expects (it doesn't accept CIDR).
func prefixToNetmask(prefix int) string {
	mask := net.CIDRMask(prefix, 32)
	return net.IP(mask).String()
}

// cleanupStack runs registered functions in reverse order, mimicking the
// defer-stack discipline. Each call's error is logged but doesn't stop
// the rest from running — we want to undo as much as possible.
type cleanupStack struct {
	mu  sync.Mutex
	fns []func() error
	ran bool
}

func (c *cleanupStack) Add(fn func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fns = append(c.fns, fn)
}

func (c *cleanupStack) Run() {
	c.mu.Lock()
	if c.ran {
		c.mu.Unlock()
		return
	}
	c.ran = true
	fns := c.fns
	c.mu.Unlock()
	for i := len(fns) - 1; i >= 0; i-- {
		if err := fns[i](); err != nil {
			log.Printf("[tun] cleanup: %v", err)
		}
	}
}
