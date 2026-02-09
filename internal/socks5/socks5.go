// Package socks5 implements a minimal SOCKS5 proxy server (RFC 1928).
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	version5 = 0x05

	authNone     = 0x00
	authUserPass = 0x02
	authNoMatch  = 0xFF

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repNotAllowed      = 0x02
	repCmdNotSupported = 0x07
	repAddrNotSupported = 0x08
)

// DialFunc dials a target address through the tunnel.
// The protocol is "tcp" or "udp".
type DialFunc func(ctx context.Context, protocol, address string) (net.Conn, error)

// Server is a SOCKS5 proxy server.
type Server struct {
	Username string
	Password string
	Dial     DialFunc
}

// ListenAndServe starts the SOCKS5 server.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("socks5 listening on %s", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("socks5 accept error: %v", err)
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := s.negotiate(conn); err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	cmd, addr, err := s.readRequest(conn)
	if err != nil {
		return
	}

	conn.SetDeadline(time.Time{})

	switch cmd {
	case cmdConnect:
		s.handleConnect(ctx, conn, addr)
	case cmdUDPAssociate:
		s.handleUDPAssociate(ctx, conn, addr)
	default:
		s.sendReply(conn, repCmdNotSupported, "0.0.0.0:0")
	}
}

func (s *Server) negotiate(conn net.Conn) error {
	// Read version + nmethods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != version5 {
		return fmt.Errorf("unsupported version %d", buf[0])
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	requireAuth := s.Username != ""

	if requireAuth {
		// Look for username/password auth
		found := false
		for _, m := range methods {
			if m == authUserPass {
				found = true
				break
			}
		}
		if !found {
			conn.Write([]byte{version5, authNoMatch})
			return fmt.Errorf("client does not support username/password auth")
		}
		conn.Write([]byte{version5, authUserPass})
		return s.authenticateUserPass(conn)
	}

	// No auth required
	conn.Write([]byte{version5, authNone})
	return nil
}

func (s *Server) authenticateUserPass(conn net.Conn) error {
	// RFC 1929 subnegotiation
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	// buf[0] = version (0x01), buf[1] = username length
	ulen := int(buf[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}
	passwd := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	if string(uname) == s.Username && string(passwd) == s.Password {
		conn.Write([]byte{0x01, 0x00}) // success
		return nil
	}
	conn.Write([]byte{0x01, 0x01}) // failure
	return fmt.Errorf("auth failed")
}

func (s *Server) readRequest(conn net.Conn) (byte, string, error) {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, "", err
	}
	if buf[0] != version5 {
		return 0, "", fmt.Errorf("unsupported version %d", buf[0])
	}
	cmd := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return 0, "", err
		}
		host = net.IP(addr).String()
	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return 0, "", err
		}
		host = net.IP(addr).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return 0, "", err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return 0, "", err
		}
		host = string(domain)
	default:
		s.sendReply(conn, repAddrNotSupported, "0.0.0.0:0")
		return 0, "", fmt.Errorf("unsupported address type %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return 0, "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return cmd, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (s *Server) handleConnect(ctx context.Context, conn net.Conn, target string) {
	remote, err := s.Dial(ctx, "tcp", target)
	if err != nil {
		log.Printf("socks5 dial %s failed: %v", target, err)
		s.sendReply(conn, repGeneralFailure, "0.0.0.0:0")
		return
	}
	defer remote.Close()

	localAddr := conn.LocalAddr().String()
	s.sendReply(conn, repSuccess, localAddr)

	// Bidirectional relay
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, remote)
		errCh <- err
	}()

	select {
	case <-errCh:
	case <-ctx.Done():
	}
}

func (s *Server) handleUDPAssociate(ctx context.Context, conn net.Conn, _ string) {
	// Bind a UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		s.sendReply(conn, repGeneralFailure, "0.0.0.0:0")
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.sendReply(conn, repGeneralFailure, "0.0.0.0:0")
		return
	}
	defer udpConn.Close()

	boundAddr := udpConn.LocalAddr().String()
	s.sendReply(conn, repSuccess, boundAddr)

	// Keep TCP connection alive - when it closes, UDP session ends
	go func() {
		buf := make([]byte, 1)
		for {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Relay UDP datagrams
	type udpSession struct {
		remote net.Conn
		client *net.UDPAddr
	}
	sessions := make(map[string]*udpSession)
	buf := make([]byte, 65536)

	udpConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return
			}
			continue
		}
		udpConn.SetReadDeadline(time.Now().Add(60 * time.Second))

		if n < 10 {
			continue
		}

		// Parse SOCKS5 UDP header
		// +----+------+------+----------+----------+----------+
		// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		// +----+------+------+----------+----------+----------+
		// | 2  |  1   |  1   | Variable |    2     | Variable |
		frag := buf[2]
		if frag != 0 {
			continue // no fragmentation support
		}

		atyp := buf[3]
		var host string
		var headerLen int
		switch atyp {
		case atypIPv4:
			if n < 10 {
				continue
			}
			host = net.IP(buf[4:8]).String()
			port := binary.BigEndian.Uint16(buf[8:10])
			host = net.JoinHostPort(host, strconv.Itoa(int(port)))
			headerLen = 10
		case atypDomain:
			dlen := int(buf[4])
			if n < 5+dlen+2 {
				continue
			}
			domain := string(buf[5 : 5+dlen])
			port := binary.BigEndian.Uint16(buf[5+dlen : 7+dlen])
			host = net.JoinHostPort(domain, strconv.Itoa(int(port)))
			headerLen = 7 + dlen
		case atypIPv6:
			if n < 22 {
				continue
			}
			host = net.IP(buf[4:20]).String()
			port := binary.BigEndian.Uint16(buf[20:22])
			host = net.JoinHostPort(host, strconv.Itoa(int(port)))
			headerLen = 22
		default:
			continue
		}

		data := buf[headerLen:n]
		key := clientAddr.String() + "->" + host

		sess, ok := sessions[key]
		if !ok {
			remote, err := s.Dial(ctx, "udp", host)
			if err != nil {
				continue
			}
			sess = &udpSession{remote: remote, client: clientAddr}
			sessions[key] = sess

			// Read responses from remote and send back to client
			go func(sess *udpSession, header []byte) {
				defer sess.remote.Close()
				rbuf := make([]byte, 65536)
				for {
					sess.remote.SetReadDeadline(time.Now().Add(60 * time.Second))
					rn, err := sess.remote.Read(rbuf)
					if err != nil {
						return
					}
					// Build SOCKS5 UDP response header + data
					resp := make([]byte, 0, len(header)+rn)
					resp = append(resp, header...)
					resp = append(resp, rbuf[:rn]...)
					udpConn.WriteToUDP(resp, sess.client)
				}
			}(sess, buf[:headerLen])
		}

		sess.remote.Write(data)
	}
}

func (s *Server) sendReply(conn net.Conn, rep byte, bindAddr string) {
	host, portStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		host = "0.0.0.0"
		portStr = "0"
	}
	port, _ := strconv.Atoi(portStr)

	reply := []byte{version5, rep, 0x00}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		reply = append(reply, atypIPv4)
		reply = append(reply, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		reply = append(reply, atypIPv6)
		reply = append(reply, ip6...)
	} else {
		reply = append(reply, atypIPv4)
		reply = append(reply, 0, 0, 0, 0)
	}
	reply = append(reply, byte(port>>8), byte(port&0xff))
	conn.Write(reply)
}
