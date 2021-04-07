package main

import (
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"regexp"
	"strings"
)

func getIPv4Addr(addresses []pcap.InterfaceAddress) net.IP {
	var ipRegex, _ = regexp.Compile("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$")

	for i := 0; i < len(addresses); i++ {
		ipAddr := addresses[i].IP
		//if net.ParseIP(ipAddr.String()) != nil && strings.Count(ipAddr.String(), ":") == 0 {
		//	return ipAddr
		//}
		if ipRegex.MatchString(ipAddr) {
			return ipAddr
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
		if handle, err = pcap.OpenLive(interfaceArg, 1600, true, pcap.BlockForever); err != nil {
			panic(err)
		}
	} else { // if interface is not provided -> go to default interface
		if devices, err = pcap.FindAllDevs(); err != nil {
			panic(err)
		} else {
			defaultInterface := devices[0]
			defaultInterfaceIP = getIPv4Addr(defaultInterface.Addresses)
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
			if packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Questions
		}

	} else {

	}

}
