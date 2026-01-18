//go:build !linux

package secure

// detectIntrusion is a stub for non-Linux platforms.
// Returns false as debugger detection is platform-specific.
// Future implementations could add Windows-specific checks:
// - IsDebuggerPresent() Win32 API
// - CheckRemoteDebuggerPresent() Win32 API
// - NtQueryInformationProcess() for ProcessDebugPort
func detectIntrusion() bool {
	// Platform-specific detection not implemented
	// Manual trigger is still available for testing
	return false
}
