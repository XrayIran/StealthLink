// Server implementation of the Conjure PT adapted for Tor
package main

import (
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	pp "github.com/pires/go-proxyproto"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil/safelog"
)

var ptInfo pt.ServerInfo

func proxy(or *net.TCPConn, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		if _, err := io.Copy(conn, or); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("Error copying OR to phantom %v", err)
		}
		or.CloseRead()
		conn.Close()
		wg.Done()
	}()
	go func() {
		if _, err := io.Copy(or, conn); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("Error copying phantom to OR %v", err)
		}
		or.CloseWrite()
		conn.Close()
		wg.Done()
	}()
	wg.Wait()
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			log.Printf("Error accepting conjure connection: %s", err)
			break
		}
		log.Printf("Received client connection from %s", conn.RemoteAddr().String())
		go func() {
			defer conn.Close()
			or, err := pt.DialOr(&ptInfo, conn.RemoteAddr().String(), "conjure")
			if err != nil {
				log.Printf("Error dialing OR port: %v", err)
			}
			defer or.Close()
			proxy(or, conn)
			log.Printf("Done proxying client connection from %s", conn.RemoteAddr().String())
		}()
	}
}

func main() {
	var allowedStationsCommas string
	var logFilename string
	var unsafeLogging bool

	flag.StringVar(&allowedStationsCommas, "allowed-stations", "", "comma-separated ip addresses of conjure stations this bridge will accept connections from")
	flag.StringVar(&logFilename, "log", "", "name of the log file")
	flag.BoolVar(&unsafeLogging, "unsafe-logging", false, "prevent logs from being scrubbed")
	flag.Parse()

	// Set up logging
	var logFile io.Writer
	logFile = ioutil.Discard
	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		logFile = f
	}
	if !unsafeLogging {
		logFile = &safelog.LogScrubber{Output: logFile}
	}
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetOutput(logFile)

	var err error
	ptInfo, err = pt.ServerSetup(nil)
	if err != nil {
		log.Fatalf("Error in setup: %s", err)
	}
	allowedStations := strings.Split(allowedStationsCommas, ",")

	//TODO: if allowed stations are empty, don't set policy?
	policy, err := pp.StrictWhiteListPolicy(allowedStations)
	if err != nil {
		log.Fatalf("Error setting haproxy policy: %s", err.Error())
	}

	listeners := make([]net.Listener, 0)
	for _, bindaddr := range ptInfo.Bindaddrs {
		if bindaddr.MethodName != "conjure" {
			pt.SmethodError(bindaddr.MethodName, "no such method")
			continue
		}

		ln, err := net.ListenTCP("tcp", bindaddr.Addr)
		if err != nil {
			log.Printf("Failed to bind to address: %v", err)
			pt.SmethodError(bindaddr.MethodName, err.Error())
		}

		haproxyListener := &pp.Listener{
			Listener:          ln,
			ReadHeaderTimeout: time.Second,
			Policy:            policy,
		}
		defer haproxyListener.Close()
		defer ln.Close()
		listeners = append(listeners, haproxyListener)
		go acceptLoop(haproxyListener)

		pt.Smethod(bindaddr.MethodName, ln.Addr())

	}
	pt.SmethodsDone()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	// https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt#n203
	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		go func() {
			if _, err := io.Copy(ioutil.Discard, os.Stdin); err != nil {
				log.Printf("Error copying os.Stdin to ioutil.Discard: %v", err)
			}
			log.Printf("Terminating because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	<-sigChan

	// Received signal, shutting down
	log.Println("Shutting down conjure server")
	for _, ln := range listeners {
		ln.Close()
	}
}
