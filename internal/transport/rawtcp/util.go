package rawtcp

import (
	"encoding/binary"
	"net"
)

func hashAddr(ip net.IP, port uint16) uint64 {
	if len(ip) == 4 {
		return uint64(binary.BigEndian.Uint32(ip))<<16 | uint64(port)
	}
	ip16 := ip.To16()
	hash := binary.BigEndian.Uint64(ip16[0:8]) ^ binary.BigEndian.Uint64(ip16[8:16])
	return hash ^ (uint64(port) << 48)
}
