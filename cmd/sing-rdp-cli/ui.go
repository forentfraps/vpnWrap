package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ui.go: the interactive CLI surface — banner, status panel, menu prompt,
// and the ANSI-color helpers that paint them.
//
// Design goal: when a user double-clicks sing-rdp-cli.exe, they get a
// readable launcher instead of a flag-help dump. When a user runs it
// with explicit flags, the menu is skipped and behaviour is unchanged.
// One binary, two modes, no .bat wrappers.

// ANSI escape codes. We zero them out at runtime if the host terminal
// won't render them (which is rare on Windows 10+ after enableANSI()
// flips ENABLE_VIRTUAL_TERMINAL_PROCESSING, but cheap insurance).
var (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cCyan   = "\x1b[36m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cRed    = "\x1b[31m"
)

func disableColor() {
	cReset, cBold, cDim, cCyan, cGreen, cYellow, cRed = "", "", "", "", "", "", ""
}

// printBanner draws the splash header. Box-drawing characters work in
// any modern Windows console once enableANSI() has flipped the output
// code page to UTF-8; on legacy code pages they show up as garbage,
// which is why we always call enableANSI() first.
func printBanner(w io.Writer) {
	// Interior width between the two ║ characters. Each banner line is
	// laid out as `║ <content>` padded out to this column with spaces,
	// then `║`. boxLine() handles the padding given the *visible*
	// width of content (ANSI escapes don't count).
	const interior = 62
	boxLine := func(visible int, content string) string {
		pad := interior - visible
		if pad < 0 {
			pad = 0
		}
		return fmt.Sprintf("  ║%s%s║\n", content, strings.Repeat(" ", pad))
	}

	// Visible widths are in columns, not bytes. ASCII chars are
	// 1 byte/1 column; the · separator is multi-byte UTF-8 but
	// occupies a single column, so we hand-count visible width
	// instead of relying on len().
	subtitleText := "RDP-wrapped VLESS VPN client"
	titleVisible := 3 + len("sing-rdp-cli") + len("  ·  ") - 1 + len("v") + len(version)
	subtitleVisible := 3 + len(subtitleText)

	title := fmt.Sprintf("   %ssing-rdp-cli%s%s  ·  v%s%s",
		cBold+cCyan, cReset, cDim, version, cReset)
	subtitle := fmt.Sprintf("   %s%s%s", cDim, subtitleText, cReset)

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  ╔%s╗\n", strings.Repeat("═", interior))
	fmt.Fprint(w, boxLine(0, ""))
	fmt.Fprint(w, boxLine(titleVisible, title))
	fmt.Fprint(w, boxLine(subtitleVisible, subtitle))
	fmt.Fprint(w, boxLine(0, ""))
	fmt.Fprintf(w, "  ╚%s╝\n", strings.Repeat("═", interior))
}

// printStatus shows the connection target read from sing-rdp.json so
// the user can sanity-check what they're about to connect to.
func printStatus(w io.Writer, cfg *Config, elevated bool) {
	row := func(label, value string) {
		fmt.Fprintf(w, "    %s%-12s%s %s\n", cDim, label, cReset, value)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %sConfig%s\n", cBold, cReset)
	row("server:", cfg.Server)
	row("sni:", cfg.SNI)
	row("hostname:", cfg.Hostname)
	row("socks5:", cfg.LocalSOCKS)
	tunStatus := cYellow + "no" + cReset + cDim + " (run as admin to enable TUN mode)" + cReset
	if elevated {
		tunStatus = cGreen + "yes" + cReset
	}
	row("admin:", tunStatus)
	fmt.Fprintln(w)
}

// menuChoice is what showMenu returns.
type menuChoice int

const (
	choiceQuit menuChoice = iota
	choiceTUN
	choiceSOCKS5
)

// showMenu draws the launch-mode picker and blocks until the user
// makes a valid selection. Default (empty input) is TUN — that's what
// "double-click and hit enter" should do for the common case.
func showMenu(w io.Writer, in io.Reader, elevated bool) menuChoice {
	fmt.Fprintf(w, "  %sWhat would you like to do?%s\n\n", cBold, cReset)

	tunHint := ""
	if !elevated {
		tunHint = cDim + " — will prompt for admin" + cReset
	}
	fmt.Fprintf(w, "    %s[1]%s  Start full VPN  %s(system-wide TUN)%s%s\n",
		cBold+cCyan, cReset, cDim, cReset, tunHint)
	fmt.Fprintf(w, "    %s[2]%s  Start SOCKS5 proxy  %s(apps connect to %s)%s\n",
		cBold+cCyan, cReset, cDim, "127.0.0.1:1080", cReset)
	fmt.Fprintf(w, "    %s[q]%s  Quit\n", cBold+cCyan, cReset)
	fmt.Fprintln(w)

	scanner := bufio.NewScanner(in)
	for {
		fmt.Fprintf(w, "  %sChoose%s [%s1%s]: ", cBold, cReset, cBold+cCyan, cReset)
		if !scanner.Scan() {
			return choiceQuit
		}
		answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
		switch answer {
		case "", "1", "tun", "vpn":
			return choiceTUN
		case "2", "socks", "socks5", "proxy":
			return choiceSOCKS5
		case "q", "quit", "exit":
			return choiceQuit
		default:
			fmt.Fprintf(w, "  %sunknown choice %q — try 1, 2, or q%s\n", cYellow, answer, cReset)
		}
	}
}

// pressEnterToClose blocks until the user hits enter. Called at the
// tail of an interactive run so a double-click launch doesn't vanish
// the console (and any error it might be showing) the instant the
// process exits.
func pressEnterToClose(w io.Writer, in io.Reader) {
	fmt.Fprintf(w, "\n  %sPress enter to close...%s ", cDim, cReset)
	bufio.NewScanner(in).Scan()
}

// stdinIsInteractive reports whether stdin is attached to a terminal
// (i.e., not a pipe / redirected file). When false, we never show the
// menu — the caller is clearly a script.
func stdinIsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
