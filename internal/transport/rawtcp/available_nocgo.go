//go:build !cgo

package rawtcp

// Available reports whether RawTCP can be used in this build/runtime environment.
func Available() (bool, string) {
	return false, "rawtcp is unavailable in this build (requires cgo + libpcap)"
}

