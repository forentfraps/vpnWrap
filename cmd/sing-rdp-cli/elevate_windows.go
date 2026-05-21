//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// elevate_windows.go: replace the old sing-rdp-vpn.bat self-elevating
// shim with two in-process Go functions:
//
//   isElevated()           — are we already running as administrator?
//   relaunchElevated(args) — spawn a new instance via ShellExecute "runas",
//                            triggering the UAC consent prompt.
//
// We use raw syscall + LazyDLL to avoid pulling in golang.org/x/sys —
// keeping the cmd/ binary's dep graph empty (see go.mod). The same
// principle applies to the enableANSI() call below: cheap stdlib path.

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")

	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
)

// isElevated reports whether the process is running with the
// Administrators-group token. We exploit the fact that
// \\.\PHYSICALDRIVE0 requires admin rights to open: cheap and correct,
// no manual SID arithmetic. (False negatives are theoretically possible
// on bizarre policy setups, but in practice the failure mode is "we
// re-prompt UAC unnecessarily", which is recoverable.)
func isElevated() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// relaunchElevated spawns the current binary again with the given
// argv tail, requesting elevation. The new process inherits the
// current working directory. If the user cancels the UAC prompt,
// ShellExecute returns code 5 (SE_ERR_ACCESSDENIED) and we report
// that distinctly so the caller can show a friendly message.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = filepath.Dir(exe)
	}

	// Build the parameter string. Quote each arg if it contains spaces.
	var sb strings.Builder
	for i, a := range args {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if strings.ContainsAny(a, " \t") {
			sb.WriteByte('"')
			sb.WriteString(a)
			sb.WriteByte('"')
		} else {
			sb.WriteString(a)
		}
	}

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	argsPtr, _ := syscall.UTF16PtrFromString(sb.String())
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)

	const swShowNormal = 1
	ret, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		swShowNormal,
	)
	if ret <= 32 {
		// ShellExecute encodes the failure in the return value. 5 is
		// "user cancelled UAC"; treat it specially so we can show a
		// nicer message than "elevation failed: errno 5".
		if ret == 5 {
			return errUserCancelled
		}
		return fmt.Errorf("ShellExecute failed: code=%d err=%v", ret, callErr)
	}
	return nil
}

// errUserCancelled signals "the user clicked No on the UAC prompt".
// Main treats this as a soft exit rather than a hard error.
var errUserCancelled = fmt.Errorf("user cancelled elevation")

// enableANSI does two things needed for our banner to render correctly
// on a default Windows console:
//
//  1. SetConsoleOutputCP(65001) — switch the output code page to UTF-8
//     so that box-drawing characters (║ ╔ ╗) and the ✓ check mark in
//     our status messages don't display as garbage like "тАФ" under
//     cp1252 / cp866.
//
//  2. ENABLE_VIRTUAL_TERMINAL_PROCESSING on the stdout console mode —
//     makes Windows 10+ interpret ANSI escape sequences for colours
//     and bold instead of printing the raw bytes literally.
//
// Both calls are safe to invoke when stdout is redirected (e.g. piped
// to a file) — the syscalls fail and we just return.
func enableANSI() {
	const cpUTF8 = 65001
	procSetConsoleOutputCP.Call(uintptr(cpUTF8))

	const enableVTProcessing = 0x0004
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	ret, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		// stdout isn't a real console — colours probably won't render
		// even if we set the mode. Strip ANSI escapes so output stays
		// readable if a user pipes us to a logfile.
		disableColor()
		return
	}
	procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVTProcessing))
}
