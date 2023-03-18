package dhcp

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Analyzer struct{}

func (a *Analyzer) AnalyzePacket(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)
	if udp.DstPort == 68 && udp.SrcPort == 67 {
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			return
		}
		dhcp := dhcpLayer.(*layers.DHCPv4)
		if dhcp.Operation == layers.DHCPOp(layers.DHCPMsgTypeOffer) {
			fmt.Printf("*** ALERT: Possible DHCP offer detected for IP address %v with MAC address %v\n", dhcp.YourClientIP, net.HardwareAddr(dhcp.ClientHWAddr))
		}
	}
}
