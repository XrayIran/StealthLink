//go:build cgo

package rawtcp

// Available reports whether RawTCP can be used in this build/runtime environment.
//
// Note: RawTCP still requires sufficient privileges (root or CAP_NET_RAW/CAP_NET_ADMIN
// depending on platform setup) at runtime. This function only captures build-time
// capability (cgo/libpcap support).
func Available() (bool, string) {
	return true, ""
}

