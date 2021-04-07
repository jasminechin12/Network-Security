package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"strings"
)

func isEthernet(packet gopacket.Packet) bool {
	if len(packet.Layers()) < 1 { return false }

	return packet.Layers()[0].LayerType().String() == "Ethernet"
}

func isICMP(packet gopacket.Packet) bool {
	if ipv4layer := packet.Layer(layers.LayerTypeIPv4); ipv4layer != nil {
		if ipv4layer.(*layers.IPv4).Protocol.String() == "ICMPv4" {
			return true
		} else { return false }
	}
	return false
}

func isTCP(packet gopacket.Packet) bool {
	if ipv4layer := packet.Layer(layers.LayerTypeIPv4); ipv4layer != nil {
		if ipv4layer.(*layers.IPv4).Protocol.String() == "TCP" {
			return true
		} else { return false }
	}
	return false
}

func isUDP(packet gopacket.Packet) bool {
	if ipv4layer := packet.Layer(layers.LayerTypeIPv4); ipv4layer != nil {
		if ipv4layer.(*layers.IPv4).Protocol.String() == "UDP" {
			return true
		} else { return false }
	}
	return false
}

func dumpPayload(packet gopacket.Packet) {
	if app := packet.ApplicationLayer(); app != nil {
		fmt.Print(hex.Dump(app.Payload()))
	} else if tp := packet.TransportLayer(); tp != nil {
		fmt.Print(hex.Dump(tp.LayerPayload()))
	} else if ntwk := packet.NetworkLayer(); ntwk != nil {
		fmt.Print(hex.Dump(ntwk.LayerPayload()))
	} else if lnk := packet.LinkLayer(); lnk != nil {
		fmt.Print(hex.Dump(lnk.LayerPayload()))
	}
}

func printPacket(packet gopacket.Packet, strArg string) {
	throwPacketAway := true

	if isEthernet(packet) {
		if strArg != "" {
			if app := packet.ApplicationLayer(); app != nil {
				if strings.Contains(string(app.Payload()), strArg) {
					throwPacketAway = false
				}
			} else if tp := packet.TransportLayer(); tp != nil {
				if strings.Contains(string(packet.TransportLayer().LayerPayload()), strArg) {
					throwPacketAway = false
				}
			} else if ntwk := packet.NetworkLayer(); ntwk != nil {
				if strings.Contains(string(ntwk.LayerPayload()), strArg) {
					throwPacketAway = false
				}
			} else if lnk := packet.LinkLayer(); lnk != nil {
				if strings.Contains(string(lnk.LayerPayload()), strArg) {
					throwPacketAway = false
				}
			}
		}

		if (strArg != "" && throwPacketAway == false) || strArg == "" {
			fmt.Print(packet.Metadata().Timestamp.Format("2006-01-02 03:04:05.000000"), " ")
			fmt.Print(packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC, " -> ", packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).DstMAC, " ")

			fmt.Printf("0x%x ", uint(packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).EthernetType))
			fmt.Print("len ", packet.Metadata().CaptureInfo.Length, " ")

			if isTCP(packet) {
				tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				fmt.Print(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP, ":", int(tcp.SrcPort), " -> ")
				fmt.Print(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP, ":", int(tcp.DstPort), " ")
				fmt.Print("TCP ")

				if tcp.FIN { fmt.Print("FIN ") }
				if tcp.SYN { fmt.Print("SYN ") }
				if tcp.RST { fmt.Print("RST ") }
				if tcp.PSH { fmt.Print("PSH ") }
				if tcp.ACK { fmt.Print("ACK ") }
				if tcp.URG { fmt.Print("URG ") }
				if tcp.ECE { fmt.Print("ECE ") }
				if tcp.CWR { fmt.Print("CWR ") }
				if tcp.NS { fmt.Print("NS ") }

			} else if isUDP(packet) {
				udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

				fmt.Print(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP, ":", int(udp.SrcPort), " -> ")
				fmt.Print(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP, ":", int(udp.DstPort), " ")
				fmt.Print("UDP ")

			} else if isICMP(packet) {
				fmt.Print(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP, " -> ", packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP, " ")
				fmt.Print("ICMP ")
			} else {
				fmt.Print("OTHER ")
			}

			fmt.Println()

			dumpPayload(packet)

			fmt.Println()
		}
	}
}

func main() {
	var interfaceArg, filename, strArg, expression string
	var handle *pcap.Handle
	var err error
	var devices []pcap.Interface
	var packetSource *gopacket.PacketSource

	for i := 1; i < len(os.Args); i += 2 {
		if os.Args[i] == "-i" {
			interfaceArg = os.Args[i+1]
		} else if os.Args[i] == "-r" {
			filename = os.Args[i+1]
		} else if os.Args[i] == "-s" {
			strArg = os.Args[i+1]
		} else {
			expression = os.Args[i]
			i -= 1
		}
	}

	if filename != "" { // check if filename is provided & give priority
		if handle, err = pcap.OpenOffline(filename); err != nil {
			panic(err)
		}
	} else if interfaceArg != "" { // check if interface is provided if filename isn't
		if handle, err = pcap.OpenLive(interfaceArg, 1600, true, pcap.BlockForever); err != nil {
			panic(err)
		}
	} else { // check if neither filename or interface is provided -> go to default interface
		if devices, err = pcap.FindAllDevs(); err != nil {
			panic(err)
		} else {
			defaultInterface := devices[0]
			if handle, err = pcap.OpenLive(defaultInterface.Name, 1600, true, pcap.BlockForever); err != nil {
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

	for packet := range packetSource.Packets() {
		printPacket(packet, strArg)
	}
}
