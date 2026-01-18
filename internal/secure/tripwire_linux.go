//go:build linux

package secure

import (
	"os"
	"strconv"
	"strings"
)

// detectIntrusion checks for debugger attachment on Linux.
// Returns true if intrusion is detected.
//
// This implementation is container-safe - it only uses the TracerPid check
// which reliably indicates if a debugger/tracer is attached. The ptrace
// self-attach method was removed because it produces false positives in
// Docker containers where ptrace is restricted by seccomp.
func detectIntrusion() bool {
	// Check if tripwire is disabled via environment variable
	// Useful for debugging or development environments
	if os.Getenv("FILEEZ_DISABLE_TRIPWIRE") == "1" {
		return false
	}

	// Check /proc/self/status for TracerPid
	// This is the reliable method that works in containers
	return checkTracerPid()
}

// checkTracerPid reads /proc/self/status to check if TracerPid is non-zero.
// A non-zero TracerPid means a process is tracing us (e.g., strace, gdb).
func checkTracerPid() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		// Can't read status - assume safe (don't false positive)
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pid, err := strconv.Atoi(parts[1])
				if err == nil && pid != 0 {
					return true // Being traced by process with this PID
				}
			}
			break
		}
	}

	return false
}
