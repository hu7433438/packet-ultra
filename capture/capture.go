package capture

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/hu7433438/packetultra/utils"
	hook "github.com/robotn/gohook"
)

var (
	Stop         bool   = false
	PacketLength uint32 = 10240
)

func GetPcapFiles(stopKey string, names ...string) {
	go setStopKey(stopKey)
	var wg sync.WaitGroup
	for device, handle := range getNetDeviceHandles(names...) {
		wg.Add(1)
		go getPackets(handle, device, &wg)
	}
	wg.Wait()
}

func setStopKey(key string) {
	ok := hook.AddEvents(key)
	if ok {
		Stop = true
	}
}

func getNetDeviceHandles(names ...string) map[string]*pcap.Handle {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var pIs []pcap.Interface
	for _, device := range devices {
		// fmt.Println("\nName: ", strconv.Itoa(i)+" "+device.Name)
		fmt.Println("\nDescription: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
		if names[0] == "any" {
			pIs = append(pIs, device)
		} else {
			for _, name := range names {
				if strings.Contains(device.Description, name) {
					pIs = append(pIs, device)
					break
				}
			}
		}
	}

	if len(pIs) == 0 {
		log.Fatalln("opening nothing, need device")
	}

	var mapHandles = make(map[string]*pcap.Handle)
	for _, device := range pIs {
		// Open the device for capturing
		handle, err := pcap.OpenLive(device.Name, int32(PacketLength), false, 5)
		if err != nil {
			log.Fatalf("Error opening device %s: %v", device.Description, err)
		}
		mapHandles[device.Description] = handle
	}
	return mapHandles
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
	writer.WriteFileHeader(PacketLength, layers.LinkTypeEthernet)

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
