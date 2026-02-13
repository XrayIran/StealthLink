//go:build cgo
// +build cgo

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func printPCAPDevices() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("  (error listing pcap devices: %v)\n", err)
		return
	}

	for _, dev := range devices {
		fmt.Printf("\nName:        %s\n", dev.Name)
		if dev.Description != "" {
			fmt.Printf("Description: %s\n", dev.Description)
		}
		if len(dev.Addresses) > 0 {
			fmt.Println("Addresses:")
			for _, addr := range dev.Addresses {
				fmt.Printf("             IP: %s", addr.IP)
				if addr.Netmask != nil {
					fmt.Printf("  Netmask: %s", addr.Netmask)
				}
				fmt.Println()
			}
		}
	}
}

func runPCAPDump(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: stealthlink-tools dump <interface> [filter]\n\nuse 'stealthlink-tools iface' to list available interfaces")
	}

	iface := args[0]
	filter := ""
	if len(args) > 1 {
		filter = args[1]
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface, err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("failed to set filter %q: %v", filter, err)
		}
		fmt.Printf("Capturing on %s with filter: %s\n", iface, filter)
	} else {
		fmt.Printf("Capturing on %s (press Ctrl+C to stop)...\n", iface)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	start := time.Now()

	for packet := range packetSource.Packets() {
		count++
		elapsed := time.Since(start)
		fmt.Printf("\n[%s] Packet #%d (%d bytes)\n", elapsed, count, len(packet.Data()))

		for _, layer := range packet.Layers() {
			fmt.Printf("  Layer: %s (%d bytes)\n", layer.LayerType(), len(layer.LayerContents()))
		}
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			fmt.Printf("  Network: %s -> %s\n", netLayer.NetworkFlow().Src(), netLayer.NetworkFlow().Dst())
		}
		if transportLayer := packet.TransportLayer(); transportLayer != nil {
			fmt.Printf("  Transport: %s -> %s\n", transportLayer.TransportFlow().Src(), transportLayer.TransportFlow().Dst())
		}
		if count >= 100 {
			fmt.Fprintln(os.Stdout, "\n(Captured 100 packets, stopping...)")
			break
		}
	}

	return nil
}
