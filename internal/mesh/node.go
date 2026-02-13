package mesh

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

const (
	ProtocolVersion     = 1
	DefaultPort         = 11010
	MaxPeers            = 256
	NATProbeTimeout     = 5 * time.Second
	PeerKeepalive       = 30 * time.Second
	PeerTimeout         = 90 * time.Second
	MaxHops             = 16
	RouteUpdateInterval = 10 * time.Second
)

type NodeType int

const (
	NodeTypeGateway NodeType = iota
	NodeTypeAgent
	NodeTypeRelay
)

type NATType int

const (
	NATUnknown NATType = iota
	NATFullCone
	NATRestricted
	NATPortRestricted
	NATSymmetric
	NATNone
)

func (n NATType) String() string {
	switch n {
	case NATFullCone:
		return "FullCone"
	case NATRestricted:
		return "Restricted"
	case NATPortRestricted:
		return "PortRestricted"
	case NATSymmetric:
		return "Symmetric"
	case NATNone:
		return "None"
	default:
		return "Unknown"
	}
}

type NodeID [32]byte

func RandomNodeID() NodeID {
	var id NodeID
	rand.Read(id[:])
	return id
}

func (id NodeID) String() string {
	return fmt.Sprintf("%x", id[:8])
}

type PeerInfo struct {
	ID          NodeID
	VirtualIP   net.IP
	PublicAddr  *net.UDPAddr
	PrivateAddr *net.UDPAddr
	NATType     NATType
	LastSeen    time.Time
	RTT         time.Duration
	Hops        int
	RelayPeer   *NodeID
}

type Route struct {
	Destination NodeID
	NextHop     NodeID
	Cost        int
	Hops        int
	Timestamp   time.Time
}

type MeshConfig struct {
	NetworkName    string
	NetworkSecret  string
	VirtualIP      net.IP
	ListenPort     int
	NodeType       NodeType
	BootstrapPeers []string
	EnableRelay    bool
	MaxPeers       int
}

type MeshNode struct {
	config        MeshConfig
	id            NodeID
	conn          *net.UDPConn
	peers         sync.Map
	routes        sync.Map
	pendingProbes sync.Map
	natType       NATType
	publicAddr    *net.UDPAddr
	virtualIP     net.IP
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	running       atomic.Bool
	mu            sync.RWMutex
}

func NewMeshNode(cfg MeshConfig) (*MeshNode, error) {
	if cfg.MaxPeers == 0 {
		cfg.MaxPeers = MaxPeers
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = DefaultPort
	}
	if cfg.VirtualIP == nil {
		cfg.VirtualIP = net.ParseIP("10.144.144.1")
	}

	ctx, cancel := context.WithCancel(context.Background())

	node := &MeshNode{
		config:    cfg,
		id:        RandomNodeID(),
		ctx:       ctx,
		cancel:    cancel,
		natType:   NATUnknown,
		virtualIP: cfg.VirtualIP,
	}

	return node, nil
}

func (n *MeshNode) Start() error {
	addr := &net.UDPAddr{Port: n.config.ListenPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	n.conn = conn

	n.running.Store(true)

	n.wg.Add(1)
	go n.receiveLoop()

	n.wg.Add(1)
	go n.keepaliveLoop()

	n.wg.Add(1)
	go n.routeMaintenanceLoop()

	n.wg.Add(1)
	go n.probeNATType()

	if len(n.config.BootstrapPeers) > 0 {
		n.wg.Add(1)
		go n.bootstrap()
	}

	metrics.SetMeshNodeActive(true)
	return nil
}

func (n *MeshNode) Stop() error {
	n.running.Store(false)
	n.cancel()
	n.wg.Wait()
	if n.conn != nil {
		n.conn.Close()
	}
	metrics.SetMeshNodeActive(false)
	return nil
}

func (n *MeshNode) receiveLoop() {
	defer n.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		n.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		nRead, raddr, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		pkt := make([]byte, nRead)
		copy(pkt, buf[:nRead])
		go n.handlePacket(pkt, raddr)
	}
}

func (n *MeshNode) handlePacket(data []byte, addr *net.UDPAddr) {
	if len(data) < 5 {
		return
	}

	msgType := data[0]
	msg := data[1:]

	switch msgType {
	case MsgTypePing:
		n.handlePing(msg, addr)
	case MsgTypePong:
		n.handlePong(msg, addr)
	case MsgTypeJoin:
		n.handleJoin(msg, addr)
	case MsgTypeLeave:
		n.handleLeave(msg, addr)
	case MsgTypeRouteUpdate:
		n.handleRouteUpdate(msg, addr)
	case MsgTypeRelay:
		n.handleRelay(msg, addr)
	case MsgTypeHolePunch:
		n.handleHolePunch(msg, addr)
	case MsgTypeData:
		n.handleData(msg, addr)
	case MsgTypeNATProbe:
		n.handleNATProbe(msg, addr)
	case MsgTypeNATProbeResp:
		n.handleNATProbeResp(msg, addr)
	}
}

const (
	MsgTypePing         = 0x01
	MsgTypePong         = 0x02
	MsgTypeJoin         = 0x03
	MsgTypeLeave        = 0x04
	MsgTypeRouteUpdate  = 0x05
	MsgTypeRelay        = 0x06
	MsgTypeHolePunch    = 0x07
	MsgTypeData         = 0x08
	MsgTypeNATProbe     = 0x09
	MsgTypeNATProbeResp = 0x0a
)

func (n *MeshNode) handlePing(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32 {
		return
	}
	var peerID NodeID
	copy(peerID[:], msg[:32])

	pong := make([]byte, 1+32+4)
	pong[0] = MsgTypePong
	copy(pong[1:33], n.id[:])
	binary.BigEndian.PutUint32(pong[33:37], uint32(time.Now().Unix()))
	n.conn.WriteToUDP(pong, addr)
	n.updatePeer(peerID, addr)
}

func (n *MeshNode) handlePong(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32 {
		return
	}
	var peerID NodeID
	copy(peerID[:], msg[:32])
	n.updatePeer(peerID, addr)
}

func (n *MeshNode) handleJoin(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32+4+2 {
		return
	}
	var peerID NodeID
	copy(peerID[:], msg[:32])
	natType := NATType(msg[32])
	port := int(binary.BigEndian.Uint16(msg[33:35]))

	peer := &PeerInfo{
		ID:         peerID,
		PublicAddr: addr,
		NATType:    natType,
		LastSeen:   time.Now(),
	}
	if port > 0 {
		peer.PrivateAddr = &net.UDPAddr{IP: addr.IP, Port: port}
	}

	n.peers.Store(peerID, peer)
	n.updateRoute(peerID, peerID, 1)

	n.sendRouteUpdate(peerID)

	metrics.IncMeshPeersJoined()
}

func (n *MeshNode) handleLeave(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32 {
		return
	}
	var peerID NodeID
	copy(peerID[:], msg[:32])

	n.peers.Delete(peerID)
	n.routes.Delete(peerID)

	metrics.IncMeshPeersLeft()
}

func (n *MeshNode) handleRouteUpdate(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32+1 {
		return
	}

	var senderID NodeID
	copy(senderID[:], msg[:32])
	n.updatePeer(senderID, addr)

	numRoutes := int(msg[32])
	offset := 33

	for i := 0; i < numRoutes && offset+36 <= len(msg); i++ {
		var destID NodeID
		copy(destID[:], msg[offset:offset+32])
		cost := int(binary.BigEndian.Uint32(msg[offset+32 : offset+36]))
		offset += 36

		if destID == n.id {
			continue
		}

		currentCost := cost + 1
		if currentCost > MaxHops {
			continue
		}

		existing, loaded := n.routes.Load(destID)
		if !loaded {
			n.routes.Store(destID, &Route{
				Destination: destID,
				NextHop:     senderID,
				Cost:        currentCost,
				Hops:        currentCost,
				Timestamp:   time.Now(),
			})
		} else {
			r := existing.(*Route)
			if currentCost < r.Cost || time.Since(r.Timestamp) > RouteUpdateInterval*2 {
				n.routes.Store(destID, &Route{
					Destination: destID,
					NextHop:     senderID,
					Cost:        currentCost,
					Hops:        currentCost,
					Timestamp:   time.Now(),
				})
			}
		}
	}
}

func (n *MeshNode) handleRelay(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32+32+1 {
		return
	}

	var targetID NodeID
	copy(targetID[:], msg[:32])

	var sourceID NodeID
	copy(sourceID[:], msg[32:64])

	data := msg[64:]

	routeVal, ok := n.routes.Load(targetID)
	if !ok {
		return
	}
	route := routeVal.(*Route)

	peerVal, ok := n.peers.Load(route.NextHop)
	if !ok {
		return
	}
	peer := peerVal.(*PeerInfo)

	relayPkt := make([]byte, 1+len(msg))
	relayPkt[0] = MsgTypeRelay
	copy(relayPkt[1:], msg)

	n.conn.WriteToUDP(relayPkt, peer.PublicAddr)

	metrics.IncMeshRelayPackets()
	_ = data
	_ = sourceID
}

func (n *MeshNode) handleHolePunch(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32 {
		return
	}

	var peerID NodeID
	copy(peerID[:], msg[:32])

	peerVal, ok := n.peers.Load(peerID)
	if !ok {
		return
	}
	peer := peerVal.(*PeerInfo)

	punchPkt := make([]byte, 1+32)
	punchPkt[0] = MsgTypeHolePunch
	copy(punchPkt[1:], n.id[:])

	for i := 0; i < 3; i++ {
		n.conn.WriteToUDP(punchPkt, peer.PublicAddr)
		if peer.PrivateAddr != nil {
			n.conn.WriteToUDP(punchPkt, peer.PrivateAddr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (n *MeshNode) handleData(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32+4 {
		return
	}

	var sourceID NodeID
	copy(sourceID[:], msg[:32])
	seq := binary.BigEndian.Uint32(msg[32:36])
	data := msg[36:]

	n.updatePeer(sourceID, addr)

	_ = seq
	_ = data
}

func (n *MeshNode) handleNATProbe(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32 {
		return
	}
	var peerID NodeID
	copy(peerID[:], msg[:32])

	resp := make([]byte, 1+32+2+2)
	resp[0] = MsgTypeNATProbeResp
	copy(resp[1:33], n.id[:])
	binary.BigEndian.PutUint16(resp[33:35], uint16(addr.Port))
	binary.BigEndian.PutUint16(resp[35:37], uint16(n.config.ListenPort))
	n.conn.WriteToUDP(resp, addr)
}

func (n *MeshNode) handleNATProbeResp(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 32+4 {
		return
	}
	var peerID NodeID
	copy(peerID[:], msg[:32])
	observedPort := binary.BigEndian.Uint16(msg[32:34])
	localPort := binary.BigEndian.Uint16(msg[34:36])

	result := struct {
		observedPort uint16
		localPort    uint16
		observedAddr *net.UDPAddr
	}{
		observedPort: observedPort,
		localPort:    localPort,
		observedAddr: addr,
	}

	n.pendingProbes.Store(peerID, result)
}

func (n *MeshNode) updatePeer(peerID NodeID, addr *net.UDPAddr) {
	val, loaded := n.peers.Load(peerID)
	if loaded {
		peer := val.(*PeerInfo)
		peer.LastSeen = time.Now()
		if peer.PublicAddr == nil || !peer.PublicAddr.IP.Equal(addr.IP) || peer.PublicAddr.Port != addr.Port {
			peer.PublicAddr = addr
		}
	} else {
		peer := &PeerInfo{
			ID:         peerID,
			PublicAddr: addr,
			LastSeen:   time.Now(),
		}
		n.peers.Store(peerID, peer)
	}
}

func (n *MeshNode) updateRoute(dest, nextHop NodeID, cost int) {
	n.routes.Store(dest, &Route{
		Destination: dest,
		NextHop:     nextHop,
		Cost:        cost,
		Hops:        cost,
		Timestamp:   time.Now(),
	})
}

func (n *MeshNode) sendRouteUpdate(targetID NodeID) {
	peerVal, ok := n.peers.Load(targetID)
	if !ok {
		return
	}
	peer := peerVal.(*PeerInfo)

	var routes []Route
	n.routes.Range(func(key, value interface{}) bool {
		r := value.(*Route)
		if r.Destination != targetID {
			routes = append(routes, *r)
		}
		return true
	})

	pkt := make([]byte, 1+32+1+len(routes)*36)
	pkt[0] = MsgTypeRouteUpdate
	copy(pkt[1:33], n.id[:])
	pkt[33] = byte(len(routes))
	offset := 34
	for _, r := range routes {
		copy(pkt[offset:offset+32], r.Destination[:])
		binary.BigEndian.PutUint32(pkt[offset+32:offset+36], uint32(r.Cost))
		offset += 36
	}

	n.conn.WriteToUDP(pkt, peer.PublicAddr)
}

func (n *MeshNode) keepaliveLoop() {
	defer n.wg.Done()

	ticker := time.NewTicker(PeerKeepalive)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.sendKeepalives()
			n.cleanupStalePeers()
		}
	}
}

func (n *MeshNode) sendKeepalives() {
	n.peers.Range(func(key, value interface{}) bool {
		peer := value.(*PeerInfo)
		ping := make([]byte, 1+32)
		ping[0] = MsgTypePing
		copy(ping[1:], n.id[:])
		n.conn.WriteToUDP(ping, peer.PublicAddr)
		if peer.PrivateAddr != nil {
			n.conn.WriteToUDP(ping, peer.PrivateAddr)
		}
		return true
	})
}

func (n *MeshNode) cleanupStalePeers() {
	now := time.Now()
	n.peers.Range(func(key, value interface{}) bool {
		peer := value.(*PeerInfo)
		if now.Sub(peer.LastSeen) > PeerTimeout {
			n.peers.Delete(key)
			n.routes.Delete(key)
			metrics.IncMeshPeersLeft()
		}
		return true
	})
}

func (n *MeshNode) routeMaintenanceLoop() {
	defer n.wg.Done()

	ticker := time.NewTicker(RouteUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.broadcastRouteUpdate()
		}
	}
}

func (n *MeshNode) broadcastRouteUpdate() {
	n.peers.Range(func(key, value interface{}) bool {
		peerID := key.(NodeID)
		n.sendRouteUpdate(peerID)
		return true
	})
}

func (n *MeshNode) probeNATType() {
	defer n.wg.Done()

	time.Sleep(2 * time.Second)

	n.peers.Range(func(key, value interface{}) bool {
		peer := value.(*PeerInfo)
		probe := make([]byte, 1+32)
		probe[0] = MsgTypeNATProbe
		copy(probe[1:], n.id[:])
		n.conn.WriteToUDP(probe, peer.PublicAddr)
		return true
	})

	time.Sleep(NATProbeTimeout)

	localPort := n.config.ListenPort
	samePort := 0
	diffPort := 0

	n.pendingProbes.Range(func(key, value interface{}) bool {
		result := value.(struct {
			observedPort uint16
			localPort    uint16
			observedAddr *net.UDPAddr
		})
		if result.observedPort == uint16(localPort) {
			samePort++
		} else {
			diffPort++
		}
		return true
	})

	if diffPort > 0 {
		n.natType = NATSymmetric
	} else if samePort > 0 {
		n.natType = NATFullCone
	} else {
		n.natType = NATUnknown
	}

	metrics.SetMeshNATType(n.natType.String())
}

func (n *MeshNode) bootstrap() {
	defer n.wg.Done()

	for _, addrStr := range n.config.BootstrapPeers {
		addr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			continue
		}

		join := make([]byte, 1+32+1+2)
		join[0] = MsgTypeJoin
		copy(join[1:33], n.id[:])
		join[33] = byte(n.natType)
		binary.BigEndian.PutUint16(join[34:36], uint16(n.config.ListenPort))

		for i := 0; i < 3; i++ {
			n.conn.WriteToUDP(join, addr)
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func (n *MeshNode) SendTo(destID NodeID, data []byte) error {
	if destID == n.id {
		return nil
	}

	routeVal, ok := n.routes.Load(destID)
	if !ok {
		return fmt.Errorf("no route to %s", destID)
	}
	route := routeVal.(*Route)

	peerVal, ok := n.peers.Load(route.NextHop)
	if !ok {
		return fmt.Errorf("next hop %s not reachable", route.NextHop)
	}
	peer := peerVal.(*PeerInfo)

	if route.Destination == route.NextHop {
		pkt := make([]byte, 1+32+4+len(data))
		pkt[0] = MsgTypeData
		copy(pkt[1:33], n.id[:])
		binary.BigEndian.PutUint32(pkt[33:37], uint32(time.Now().UnixNano()))
		copy(pkt[37:], data)
		return n.sendWithHolePunch(peer, pkt)
	}

	relay := make([]byte, 1+32+32+4+len(data))
	relay[0] = MsgTypeRelay
	copy(relay[1:33], destID[:])
	copy(relay[33:65], n.id[:])
	binary.BigEndian.PutUint32(relay[65:69], uint32(time.Now().UnixNano()))
	copy(relay[69:], data)

	nextPeerVal, ok := n.peers.Load(route.NextHop)
	if !ok {
		return fmt.Errorf("relay next hop not found")
	}
	nextPeer := nextPeerVal.(*PeerInfo)
	n.conn.WriteToUDP(relay, nextPeer.PublicAddr)

	metrics.IncMeshRelayPackets()
	return nil
}

func (n *MeshNode) sendWithHolePunch(peer *PeerInfo, pkt []byte) error {
	if peer.NATType == NATSymmetric || peer.NATType == NATPortRestricted || peer.NATType == NATRestricted {
		punch := make([]byte, 1+32)
		punch[0] = MsgTypeHolePunch
		copy(punch[1:], n.id[:])

		for i := 0; i < 3; i++ {
			n.conn.WriteToUDP(punch, peer.PublicAddr)
			if peer.PrivateAddr != nil {
				n.conn.WriteToUDP(punch, peer.PrivateAddr)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	_, err := n.conn.WriteToUDP(pkt, peer.PublicAddr)
	return err
}

func (n *MeshNode) GetPeers() []PeerInfo {
	var peers []PeerInfo
	n.peers.Range(func(key, value interface{}) bool {
		peer := value.(*PeerInfo)
		peers = append(peers, *peer)
		return true
	})
	return peers
}

func (n *MeshNode) GetRoutes() []Route {
	var routes []Route
	n.routes.Range(func(key, value interface{}) bool {
		route := value.(*Route)
		routes = append(routes, *route)
		return true
	})
	return routes
}

func (n *MeshNode) GetNATType() NATType {
	return n.natType
}

func (n *MeshNode) GetID() NodeID {
	return n.id
}

func (n *MeshNode) GetVirtualIP() net.IP {
	return n.virtualIP
}

func (n *MeshNode) EstablishP2P(peerID NodeID) error {
	peerVal, ok := n.peers.Load(peerID)
	if !ok {
		return fmt.Errorf("peer not found")
	}
	peer := peerVal.(*PeerInfo)

	switch {
	case n.natType == NATNone && peer.NATType == NATNone:
		return nil
	case n.natType == NATFullCone || peer.NATType == NATFullCone:
		return n.initiateHolePunch(peer)
	case n.natType != NATSymmetric && peer.NATType != NATSymmetric:
		return n.initiateHolePunch(peer)
	default:
		if n.config.EnableRelay {
			return nil
		}
		return fmt.Errorf("cannot establish P2P: both symmetric NAT")
	}
}

func (n *MeshNode) initiateHolePunch(peer *PeerInfo) error {
	punch := make([]byte, 1+32)
	punch[0] = MsgTypeHolePunch
	copy(punch[1:], n.id[:])

	for i := 0; i < 5; i++ {
		n.conn.WriteToUDP(punch, peer.PublicAddr)
		if peer.PrivateAddr != nil {
			n.conn.WriteToUDP(punch, peer.PrivateAddr)
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}
