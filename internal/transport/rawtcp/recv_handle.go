//go:build cgo
// +build cgo

package rawtcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle *pcap.Handle

	mu        sync.RWMutex
	addrCache map[addrKey]*net.UDPAddr
}

func NewRecvHandle(cfg *packetConfig) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("pcap handle: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("set pcap direction in: %v", err)
		}
	}

	filter := buildBPFFilter(cfg)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}

	rh := &RecvHandle{
		handle:    handle,
		addrCache: make(map[addrKey]*net.UDPAddr, 1024),
	}
	return rh, nil
}

// buildBPFFilter constructs a BPF filter appropriate for the configured profile.
// Profiles:
//   - "basic" (default): tcp and dst port N
//   - "strict": keeps likely transport frames (ACK/PSH-bearing segments)
//   - "stealth": strict + drops obvious scanner flag patterns without
//     blacklisting source ports used by legitimate deployments (e.g. 443).
func buildBPFFilter(cfg *packetConfig) string {
	base := fmt.Sprintf("tcp and dst port %d", cfg.port)

	bpfProfile := "basic"
	if len(cfg.bpfProfile) > 0 {
		bpfProfile = cfg.bpfProfile
	}

	switch bpfProfile {
	case "strict":
		// Keep segments used by this transport while reducing unrelated noise.
		return fmt.Sprintf("(%s) and (tcp[tcpflags] & (tcp-push|tcp-ack) != 0)", base)
	case "stealth":
		// Avoid source-port blacklists (they can break real tunnels on 443/80).
		// Instead suppress common unsolicited probe signatures:
		// - pure SYN (scan/init without data path semantics)
		// - any RST segments
		// - pure ECE / CWR probes (commonly used by scanners)
		return fmt.Sprintf("(%s) and (tcp[tcpflags] & (tcp-push|tcp-ack) != 0) and not (tcp[tcpflags] & tcp-rst != 0) and not (tcp[tcpflags] = tcp-syn) and not (tcp[tcpflags] & 0xc0 != 0 and tcp[tcpflags] & (tcp-push|tcp-ack) = 0)", base)
	default:
		return base
	}
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	for {
		data, _, err := h.handle.ZeroCopyReadPacketData()
		if err != nil {
			return nil, nil, err
		}
		srcIP, srcPort, payload, ok := parseEtherIPTCP(data)
		if !ok || len(payload) == 0 {
			continue
		}
		addr := h.getAddr(srcIP, srcPort)
		return payload, addr, nil
	}
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}

type addrKey struct {
	ip   [16]byte
	port uint16
	v4   bool
}

const maxAddrCache = 65536

func (h *RecvHandle) getAddr(srcIP []byte, srcPort uint16) *net.UDPAddr {
	var k addrKey
	k.port = srcPort
	if len(srcIP) == 4 {
		k.v4 = true
		copy(k.ip[:4], srcIP)
	} else {
		copy(k.ip[:], srcIP)
	}

	h.mu.RLock()
	if a := h.addrCache[k]; a != nil {
		h.mu.RUnlock()
		return a
	}
	h.mu.RUnlock()

	var ipCopy net.IP
	if k.v4 {
		ipCopy = make(net.IP, 4)
		copy(ipCopy, srcIP[:4])
	} else {
		ipCopy = make(net.IP, 16)
		copy(ipCopy, srcIP[:16])
	}
	addr := &net.UDPAddr{IP: ipCopy, Port: int(srcPort)}

	h.mu.Lock()
	if len(h.addrCache) >= maxAddrCache {
		h.addrCache = make(map[addrKey]*net.UDPAddr, 1024)
	}
	if a := h.addrCache[k]; a != nil {
		h.mu.Unlock()
		return a
	}
	h.addrCache[k] = addr
	h.mu.Unlock()

	return addr
}

func parseEtherIPTCP(frame []byte) (srcIP []byte, srcPort uint16, payload []byte, ok bool) {
	const (
		etherHdrLen  = 14
		ethIPv4      = 0x0800
		ethIPv6      = 0x86DD
		ethVLAN      = 0x8100
		ethQinQ      = 0x88A8
		ipProtoTCP   = 6
		ipv4MinHdr   = 20
		ipv6HdrLen   = 40
		tcpMinHdrLen = 20
	)

	if len(frame) < etherHdrLen {
		return nil, 0, nil, false
	}
	off := etherHdrLen
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType == ethVLAN || etherType == ethQinQ {
		if len(frame) < etherHdrLen+4 {
			return nil, 0, nil, false
		}
		etherType = binary.BigEndian.Uint16(frame[16:18])
		off += 4
	}

	switch etherType {
	case ethIPv4:
		if len(frame) < off+ipv4MinHdr {
			return nil, 0, nil, false
		}
		ihl := int(frame[off]&0x0F) * 4
		if ihl < ipv4MinHdr || len(frame) < off+ihl {
			return nil, 0, nil, false
		}
		if frame[off+9] != ipProtoTCP {
			return nil, 0, nil, false
		}
		src := frame[off+12 : off+16]
		tcpOff := off + ihl
		if len(frame) < tcpOff+tcpMinHdrLen {
			return nil, 0, nil, false
		}
		dataOff := int(frame[tcpOff+12]>>4) * 4
		if dataOff < tcpMinHdrLen || len(frame) < tcpOff+dataOff {
			return nil, 0, nil, false
		}
		sport := binary.BigEndian.Uint16(frame[tcpOff : tcpOff+2])
		return src, sport, frame[tcpOff+dataOff:], true

	case ethIPv6:
		if len(frame) < off+ipv6HdrLen {
			return nil, 0, nil, false
		}
		next := frame[off+6]
		src := frame[off+8 : off+24]
		tcpOff := off + ipv6HdrLen

		for {
			switch next {
			case ipProtoTCP:
				if len(frame) < tcpOff+tcpMinHdrLen {
					return nil, 0, nil, false
				}
				dataOff := int(frame[tcpOff+12]>>4) * 4
				if dataOff < tcpMinHdrLen || len(frame) < tcpOff+dataOff {
					return nil, 0, nil, false
				}
				sport := binary.BigEndian.Uint16(frame[tcpOff : tcpOff+2])
				return src, sport, frame[tcpOff+dataOff:], true

			case 0, 43, 60:
				if len(frame) < tcpOff+2 {
					return nil, 0, nil, false
				}
				extNext := frame[tcpOff]
				extLen := int(frame[tcpOff+1]+1) * 8
				if len(frame) < tcpOff+extLen {
					return nil, 0, nil, false
				}
				next = extNext
				tcpOff += extLen
				continue

			case 44:
				if len(frame) < tcpOff+8 {
					return nil, 0, nil, false
				}
				next = frame[tcpOff]
				tcpOff += 8
				continue

			case 51:
				if len(frame) < tcpOff+2 {
					return nil, 0, nil, false
				}
				extNext := frame[tcpOff]
				extLen := (int(frame[tcpOff+1]) + 2) * 4
				if len(frame) < tcpOff+extLen {
					return nil, 0, nil, false
				}
				next = extNext
				tcpOff += extLen
				continue

			default:
				return nil, 0, nil, false
			}
		}

	default:
		return nil, 0, nil, false
	}
}
