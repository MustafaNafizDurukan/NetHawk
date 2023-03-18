package tcp

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Analyzer struct{}

func (a *Analyzer) AnalyzePacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)
	if tcp.SYN && !tcp.ACK {
		fmt.Printf("*** ALERT: Possible TCP scan detected from IP address %v\n", packet.NetworkLayer().NetworkFlow().Src().String())
	}
}
