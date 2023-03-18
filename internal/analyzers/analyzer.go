package analyzers

import (
	"deneme/internal/analyzers/arp"
	"deneme/internal/analyzers/dhcp"
	"deneme/internal/analyzers/dns"
	"deneme/internal/analyzers/ethernet"
	"deneme/internal/analyzers/icmp"
	"deneme/internal/analyzers/ip"
	"deneme/internal/analyzers/tcp"
	"deneme/internal/analyzers/udp"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IAnalyzer interface {
	AnalyzePacket(packet gopacket.Packet)
}

func Run(packet gopacket.Packet) {
	AnalyzeLinkLayer(packet)
	AnalyzeNetworkLayer(packet)
	AnalyzeTransportLayer(packet)
	AnalyzeApplicationLayer(packet)
}

func AnalyzeLinkLayer(packet gopacket.Packet) {
	layer := packet.LinkLayer()
	switch layer.LayerType() {
	case layers.LayerTypeEthernet:
		ethernetAnalyzer := &ethernet.Analyzer{}
		ethernetAnalyzer.AnalyzePacket(packet)
	default:
		fmt.Println("Unknown Link Layer Type")
	}
}

func AnalyzeNetworkLayer(packet gopacket.Packet) {
	layer := packet.NetworkLayer()
	switch layer.LayerType() {
	case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
		ipv4Analyzer := &ip.Analyzer{}
		ipv4Analyzer.AnalyzePacket(packet)
	case layers.LayerTypeARP:
		arpAnalyzer := &arp.Analyzer{}
		arpAnalyzer.AnalyzePacket(packet)
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
		icmpv4Analyzer := &icmp.Analyzer{}
		icmpv4Analyzer.AnalyzePacket(packet)
	default:
		fmt.Println("Unknown Network Layer Type")
	}
}

func AnalyzeTransportLayer(packet gopacket.Packet) {
	layer := packet.TransportLayer()
	switch layer.LayerType() {
	case layers.LayerTypeTCP:
		tcpAnalyzer := &tcp.Analyzer{}
		tcpAnalyzer.AnalyzePacket(packet)
	case layers.LayerTypeUDP:
		udpAnalyzer := &udp.Analyzer{}
		udpAnalyzer.AnalyzePacket(packet)
	default:
		fmt.Println("Unknown Transport Layer Type")
	}
}

func AnalyzeApplicationLayer(packet gopacket.Packet) {
	layer := packet.ApplicationLayer()
	switch layer.LayerType() {
	case layers.LayerTypeDHCPv4, layers.LayerTypeDHCPv6:
		dhcpv4Analyzer := &dhcp.Analyzer{}
		dhcpv4Analyzer.AnalyzePacket(packet)
	case layers.LayerTypeDNS:
		dnsAnalyzer := &dns.Analyzer{}
		dnsAnalyzer.AnalyzePacket(packet)
	default:
		fmt.Println("Unknown Application Layer Type")
	}
}
