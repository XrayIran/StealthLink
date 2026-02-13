//go:build cgo
// +build cgo

package rawtcp

import (
	"fmt"
	"runtime"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

func newHandle(cfg *packetConfig) (*pcap.Handle, error) {
	ifaceName := cfg.iface.Name
	if runtime.GOOS == "windows" && cfg.guid != "" {
		ifaceName = cfg.guid
	}

	inactive, err := pcap.NewInactiveHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("create inactive handle for %s: %v", cfg.iface.Name, err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetBufferSize(cfg.sockbuf); err != nil {
		return nil, fmt.Errorf("set pcap buffer size to %d: %v", cfg.sockbuf, err)
	}
	if err = inactive.SetSnapLen(cfg.snaplen); err != nil {
		return nil, fmt.Errorf("set pcap snap length to %d: %v", cfg.snaplen, err)
	}
	// Promisc defaults to true if not explicitly set
	promisc := cfg.promisc
	if !promisc && cfg.snaplen == 65536 {
		// If snaplen is default and promisc not explicitly set, use true
		promisc = true
	}
	if err = inactive.SetPromisc(promisc); err != nil {
		return nil, fmt.Errorf("set promiscuous mode to %v: %v", promisc, err)
	}
	// Timeout: 0 or negative means block forever
	timeout := pcap.BlockForever
	if cfg.timeoutMs > 0 {
		timeout = time.Duration(cfg.timeoutMs) * time.Millisecond
	}
	if err = inactive.SetTimeout(timeout); err != nil {
		return nil, fmt.Errorf("set pcap timeout to %v: %v", timeout, err)
	}
	// Immediate mode: defaults to true if not explicitly set to false
	immediate := cfg.immediate
	if !immediate && cfg.timeoutMs == 0 {
		// If timeout is default (block forever) and immediate not set, use true
		immediate = true
	}
	if err = inactive.SetImmediateMode(immediate); err != nil {
		return nil, fmt.Errorf("set immediate mode to %v: %v", immediate, err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate pcap handle on %s: %v", cfg.iface.Name, err)
	}

	return handle, nil
}
