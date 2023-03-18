package main

import (
	"deneme/internal/analyzers"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Set network interface to capture packets from
	ifaceName := "eth0"

	// Open network interface for packet capture
	handle, err := pcap.OpenLive(ifaceName, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Iterate over packets and analyze them using appropriate analyzer
	for packet := range packetSource.Packets() {
		analyzers.Run(packet)
	}
}
