package icmp

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Analyzer struct{}

func (a *Analyzer) AnalyzePacket(packet gopacket.Packet) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return
	}
	icmp := icmpLayer.(*layers.ICMPv4)
	if icmp.TypeCode.String() == "EchoRequest(EchoRequest)" {
		fmt.Printf("*** ALERT: Possible ICMP echo request detected from IP address %v\n", packet.NetworkLayer().NetworkFlow().Src().String())
	}
}
