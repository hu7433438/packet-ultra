package capture

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/hu7433438/packetultra/utils"
	hook "github.com/robotn/gohook"
)

var Stop bool = false

func GetPcapFiles(names ...string) {
	go setStopKey("esc")
	var wg sync.WaitGroup
	for i, d := range getNetDeviceHandles(names...) {
		wg.Add(1)
		go getPackets(d, strconv.Itoa(i), &wg)
	}
	wg.Wait()
}

func setStopKey(key string) {
	ok := hook.AddEvents(key)
	if ok {
		Stop = true
	}
}

func getNetDeviceHandles(names ...string) []*pcap.Handle {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	if names[0] == "any" {
		names = nil
		for i, device := range devices {
			names = append(names, device.Name)
			fmt.Println("\nName: ", strconv.Itoa(i)+" "+device.Name)
			fmt.Println("Description: ", device.Description)
			for _, address := range device.Addresses {
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
			}
		}
	}
	// todo 使用设备全称编写
	var Handles []*pcap.Handle
	for _, device := range names {
		// Open the device for capturing
		handle, err := pcap.OpenLive(device, 1024, false, 5)
		if err != nil {
			log.Fatalf("Error opening device %s: %v", device, err)
		}
		Handles = append(Handles, handle)
	}
	return Handles
}

func getPackets(handle *pcap.Handle, pcapFile string, wg *sync.WaitGroup) {
	defer wg.Done()
	pcapFile = pcapFile + ".pcap"
	if utils.Exists(pcapFile) {
		os.Remove(pcapFile)
	}

	f, _ := os.Create(pcapFile)
	defer f.Close()
	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(1024, layers.LinkTypeEthernet)

	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

Write:
	for !Stop {
		select {
		case packet := <-packetSource.Packets():
			fmt.Println(packet)
			writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		case <-time.After(5 * time.Second):
			break Write
		}
	}
}
