package main

import (
	"flag"
	"net"
	"os"
	"sync"
)

func readFromServer(waitTimer sync.WaitGroup ,connection net.Conn) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 1024)
		numOfBytes, err := connection.Read(buffer)
		if err != nil { break }
		//_, err = os.Stderr.WriteString("Reading from server")
		_, err = os.Stdout.Write(buffer[:numOfBytes])
		if err != nil { break }
	}
}

func writeToServer(waitTimer sync.WaitGroup,connection net.Conn) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 1024)
		numOfBytes, err := os.Stdin.Read(buffer)
		//_, err = os.Stderr.WriteString("Writing to server")
		_, err = connection.Write(buffer[:numOfBytes])
		if err != nil { break }
	}
}

func listenFromClient(waitTimer sync.WaitGroup, connection net.Conn, return_connection net.Conn) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 1024)
		numOfBytes, err := connection.Read(buffer)
		if err != nil { break }
		// encrypt here
		//_, err = os.Stderr.WriteString("Reading from client")
		_, err = return_connection.Write(buffer[:numOfBytes])
		if err != nil { break }
	}
}

func writeToClient(waitTimer sync.WaitGroup, connection net.Conn, return_connection net.Conn) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 1024)
		numOfBytes, err := return_connection.Read(buffer)
		if err != nil { break }
		// encrypt here
		//_, err = os.Stderr.WriteString("Writing to client")
		_, err = connection.Write(buffer[:numOfBytes])
		if err != nil { break }
	}
}

func handleConnections(connection net.Conn, return_connection net.Conn) {
	var waitTimer sync.WaitGroup
	waitTimer.Add(2) // keep track of goroutines (read from client and writing to client)
	//_, err := os.Stderr.WriteString("Handling connection")
	//if err != nil { panic(err) }
	go listenFromClient(waitTimer, connection, return_connection)
	go writeToClient(waitTimer, connection, return_connection)
	waitTimer.Wait()
}

func main() {
	var listenport, pwdfile, destination, port string

	flag.StringVar(&listenport, "l", "", "listenport")
	flag.StringVar(&pwdfile, "p", "", "passphrase")

	flag.Parse()

	destination = flag.Arg(0)
	port = ":" + flag.Arg(1)

	pwdfile = pwdfile

	if listenport == "" { // client mode
		server, err := net.Dial("tcp", destination+port)
		if err != nil { panic(err) }

		var waitTimer sync.WaitGroup
		waitTimer.Add(2)

		go readFromServer(waitTimer ,server)
		go writeToServer(waitTimer, server)
		waitTimer.Wait()

	} else { // reverse-proxy mode
		listener, err := net.Listen("tcp", ":"+listenport)
		if err != nil { panic(err) }
		//_, err = os.Stderr.WriteString("Entered Reverse Proxy Mode")
		for {
			connection, err := listener.Accept()
			//if err != nil { break } else { _, err = os.Stderr.WriteString("Accepted connection")}
			//_, err = os.Stderr.WriteString(destination+port)
			return_connection, err := net.Dial("tcp", destination+port)
			if err != nil {
				continue
			} else {
				go handleConnections(connection, return_connection)
			}
		}
	}
}