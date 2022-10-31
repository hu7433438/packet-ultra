package main

import (
	"github.com/hu7433438/packetultra/capture"
)

func main() {
	capture.GetPcapFiles("esc", "Qualcomm QCA9377 802.11ac Wireless Adapter")
	// capture.GetPcapFiles("esc", "any")
}
