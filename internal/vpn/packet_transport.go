package vpn

import (
	"net"

	"stealthlink/internal/relay"
	"stealthlink/internal/transport"
)

// PacketTransport moves whole IP packets between peers (as opposed to a byte stream).
// Implementations must make Close unblock a blocked ReceivePacket call.
type PacketTransport interface {
	SendPacket(pkt []byte) error
	ReceivePacket() ([]byte, error)
	Close() error
}

type streamPacketTransport struct {
	conn net.Conn
}

func NewStreamPacketTransport(conn net.Conn) PacketTransport {
	return &streamPacketTransport{conn: conn}
}

func (t *streamPacketTransport) SendPacket(pkt []byte) error {
	return relay.WriteFrame(t.conn, pkt)
}

func (t *streamPacketTransport) ReceivePacket() ([]byte, error) {
	return relay.ReadFrame(t.conn)
}

func (t *streamPacketTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

type datagramPacketTransport struct {
	sess transport.DatagramSession
	id   uint32
}

func NewDatagramPacketTransport(sess transport.DatagramSession, sessionID uint32) PacketTransport {
	return &datagramPacketTransport{sess: sess, id: sessionID}
}

func (t *datagramPacketTransport) SendPacket(pkt []byte) error {
	return t.sess.SendDatagram(t.id, pkt)
}

func (t *datagramPacketTransport) ReceivePacket() ([]byte, error) {
	return t.sess.ReceiveDatagram(t.id)
}

func (t *datagramPacketTransport) Close() error {
	return t.sess.CloseDatagramSession(t.id)
}
