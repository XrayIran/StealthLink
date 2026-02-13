//go:build !cgo
// +build !cgo

package main

import "fmt"

func printPCAPDevices() {
	fmt.Println("  (pcap unavailable in this build: cgo/libpcap disabled)")
}

func runPCAPDump(_ []string) error {
	return fmt.Errorf("pcap dump is unavailable in this build: cgo/libpcap disabled")
}
