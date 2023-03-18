package udp

import (
	"fmt"
	"strings"

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
	if udp.DstPort == 53 {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			return
		}
		dns := dnsLayer.(*layers.DNS)
		for _, question := range dns.Questions {
			fmt.Printf("*** ALERT: Possible DNS query for %v detected from IP address %v\n", strings.TrimSuffix(string(question.Name), "."), packet.NetworkLayer().NetworkFlow().Src().String())
		}
	}
}
