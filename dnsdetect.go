package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type packetInfo struct {
	TXID      uint16
	Hostname  []byte
	IP        []net.IP
	Timestamp time.Time
}

func getListOfIP(packet gopacket.Packet) []net.IP {
	answers := packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers
	var ipAddresses []net.IP

	for record := range answers {
		ipAddresses = append(ipAddresses, answers[record].IP)
	}

	return ipAddresses
}

func printResponses(packet gopacket.Packet, initialResponse packetInfo) {
	fmt.Println(packet.Metadata().Timestamp.Format("2006-01-02 03:04:05.000000"), " ")
	fmt.Println("TXID", initialResponse.TXID, "Request", string(initialResponse.Hostname))
	fmt.Printf("Answer1 %+v\n", initialResponse.IP)

	ipAddresses := getListOfIP(packet)

	fmt.Printf("Answer2 %+v\n", ipAddresses)
}

func main() {
	var interfaceArg, tracefile, expression string
	var handle *pcap.Handle
	var err error
	var devices []pcap.Interface
	var packetSource *gopacket.PacketSource

	for i := 1; i < len(os.Args); i += 2 {
		if os.Args[i] == "-i" {
			interfaceArg = os.Args[i+1]
		} else if os.Args[i] == "-r" {
			tracefile = os.Args[i+1]
		} else {
			expression = os.Args[i]
			i -= 1
		}
	}

	if tracefile != "" { // give priority to file
		if handle, err = pcap.OpenOffline(tracefile); err != nil {
			panic(err)
		}
	} else if interfaceArg != "" { // check if interface is provided
		if handle, err = pcap.OpenLive(interfaceArg, 3000, true, pcap.BlockForever); err != nil {
			panic(err)
		}
	} else { // if interface is not provided -> go to default interface
		if devices, err = pcap.FindAllDevs(); err != nil {
			panic(err)
		} else {
			defaultInterface := devices[0]
			if handle, err = pcap.OpenLive(defaultInterface.Name, 3000, true, pcap.BlockForever); err != nil {
				panic(err)
			}
		}
	}

	if expression != "" {
		if err = handle.SetBPFFilter(strings.ToLower(expression)); err != nil {
			panic(err)
		}
	}

	packetSource = gopacket.NewPacketSource(handle, handle.LinkType())

	dnsQueries := make(map[string]packetInfo)

	for packet := range packetSource.Packets() {
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			if questions := dnsLayer.(*layers.DNS).Questions; questions != nil {
				if questions[0].Type == layers.DNSTypeA && dnsLayer.(*layers.DNS).QR == true {
					key := strconv.Itoa(int(dnsLayer.(*layers.DNS).ID)) + "|" + string(questions[0].Name)
					if value, found := dnsQueries[key]; found {
						packetTime := packet.Metadata().Timestamp
						if packetTime.Sub(value.Timestamp).Seconds() <= 5 {
							printResponses(packet, value)
						} else {
							ipAddresses := getListOfIP(packet)
							dnsQueries[key] = packetInfo{TXID: dnsLayer.(*layers.DNS).ID, Hostname: dnsLayer.(*layers.DNS).Questions[0].Name, IP: ipAddresses, Timestamp: packetTime}
						}
					} else {
						ipAddresses := getListOfIP(packet)
						dnsQueries[key] = packetInfo{TXID: dnsLayer.(*layers.DNS).ID, Hostname: dnsLayer.(*layers.DNS).Questions[0].Name, IP: ipAddresses, Timestamp: packet.Metadata().Timestamp}
					}
				}
			}
		}
	}
}
