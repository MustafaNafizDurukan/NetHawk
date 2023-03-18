package arp

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Analyzer struct{}

func (a *Analyzer) AnalyzePacket(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}
	arp := arpLayer.(*layers.ARP)
	if arp.Operation == layers.ARPRequest {
		fmt.Printf("*** ALERT: Possible ARP request detected from IP address %v with MAC address %v\n", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
	}
}
