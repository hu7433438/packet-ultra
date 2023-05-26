package main

import (
	"flag"

	"github.com/hu7433438/packetultra/capture"
)

var (
	stopKey  = flag.String("s", "esc", "stopKey")
	device   = flag.String("d", "any", "devices des")
	pcapPath = flag.String("p", "pcap", "pcapPath")
)

func main() {
	flag.Parse()
	// capture.GetPcapFiles("esc", "Qualcomm QCA9377 802.11ac Wireless Adapter")
	capture.GetPcapFiles(*stopKey, *pcapPath, *device)
}
