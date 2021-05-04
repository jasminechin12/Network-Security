package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

func encryptMessage(data []byte, passphrase []byte) []byte {
	passphraseSalt := generateSalt()
	key := pbkdf2.Key(passphrase, passphraseSalt, 4096, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	decrypt_info := append(passphraseSalt, nonce...)

	encryptedMessage := aesgcm.Seal(decrypt_info, nonce, data, nil)

	return encryptedMessage
}

func decryptMessage(data []byte, passphrase []byte) []byte{
	passphraseSalt := data[:16]
	key := pbkdf2.Key(passphrase, passphraseSalt, 4096, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := data[16:16+aesgcm.NonceSize()]
	encryptedMessage := data[16+aesgcm.NonceSize():]

	plaintext, err := aesgcm.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		panic(err)
	}

	return plaintext
}

func generateSalt () []byte {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}
	return salt
}

func writeToServer(waitTimer sync.WaitGroup, connection net.Conn, passphrase []byte) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 5000)
		numOfBytes, err := os.Stdin.Read(buffer)
		if err != nil { break}

		encryptedMessage := encryptMessage(buffer[:numOfBytes], passphrase)

		_, err = connection.Write(encryptedMessage)
		if err != nil { break }
	}
}

func readFromServer(waitTimer sync.WaitGroup , connection net.Conn, passphrase []byte) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 5000)
		numOfBytes, err := connection.Read(buffer)
		if err != nil { break }

		decryptedMessage := decryptMessage(buffer[:numOfBytes], passphrase)

		_, err = os.Stdout.Write(decryptedMessage)
		if err != nil { break }
	}
}

func writeToDestination(waitTimer sync.WaitGroup, connection net.Conn, return_connection net.Conn, passphrase []byte) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 5000)
		numOfBytes, err := connection.Read(buffer)
		if err != nil { break }

		decryptedMessage := decryptMessage(buffer[:numOfBytes], passphrase)

		_, err = return_connection.Write(decryptedMessage)
		if err != nil { break }
	}
}

func readFromDestination(waitTimer sync.WaitGroup, connection net.Conn, return_connection net.Conn, passphrase []byte) {
	defer waitTimer.Done()
	for {
		buffer := make([]byte, 5000)
		numOfBytes, err := return_connection.Read(buffer)
		if err != nil { break }

		encryptedMessage := encryptMessage(buffer[:numOfBytes], passphrase)

		_, err = connection.Write(encryptedMessage)
		if err != nil { break }
	}
}

func handleConnections(connection net.Conn, return_connection net.Conn, passphrase []byte) {
	var waitTimer sync.WaitGroup
	waitTimer.Add(2) // keep track of goroutines (read from client and writing to client)

	go readFromDestination(waitTimer, connection, return_connection, passphrase)
	go writeToDestination(waitTimer, connection, return_connection, passphrase)
	waitTimer.Wait()
}

func main() {
	var listenport, pwdfile, destination, port string

	flag.StringVar(&listenport, "l", "", "listenport")
	flag.StringVar(&pwdfile, "p", "", "passphrase")

	flag.Parse()

	destination = flag.Arg(0)
	port = ":" + flag.Arg(1)

	file, err := os.Open(pwdfile)
	if err != nil { panic(err) }

	passphrase := make([]byte, 5000)
	numOfBytes, err := file.Read(passphrase)

	if listenport == "" { // client mode
		server, err := net.Dial("tcp", destination+port)
		if err != nil { panic(err) }

		var waitTimer sync.WaitGroup
		waitTimer.Add(2)

		go readFromServer(waitTimer ,server, passphrase[:numOfBytes])
		go writeToServer(waitTimer, server, passphrase[:numOfBytes])
		waitTimer.Wait()

	} else { // reverse-proxy mode
		listener, err := net.Listen("tcp", ":"+listenport)
		if err != nil { panic(err) }
		for {
			connection, err := listener.Accept()
			return_connection, err := net.Dial("tcp", destination+port)
			if err != nil {
				continue
			} else {
				go handleConnections(connection, return_connection, passphrase[:numOfBytes])
			}
		}
	}
}