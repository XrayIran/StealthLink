package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/authn"
	"stealthlink/internal/config"
	"stealthlink/internal/control"
	"stealthlink/internal/metrics"
	"stealthlink/internal/mux"
	"stealthlink/internal/netutil"
	"stealthlink/internal/ratelimit"
	"stealthlink/internal/relay"
	"stealthlink/internal/security/bloom"
	"stealthlink/internal/socks5"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/noize"
	stealthtx "stealthlink/internal/transport/stealth"
	"stealthlink/internal/transport/uqsp"
	"stealthlink/internal/tun"
	"stealthlink/internal/vpn"
	"stealthlink/internal/warp"

	"github.com/xtaci/smux"
)

const (
	udpIdleTimeout = 60 * time.Second
	pingInterval   = 10 * time.Second
	pingTimeout    = 5 * time.Second
)

type Gateway struct {
	cfg        *config.Config
	registry   *registry
	svcByName  map[string]config.Service
	limiter    *mux.Limiter
	svcLimits  map[string]*mux.Limiter
	svcACL     map[string][]*net.IPNet
	acceptKeys []string
	writeKey   string
	replay     *bloom.Filter
}

type registry struct {
	mu       sync.RWMutex
	services map[string]*servicePool
}

type servicePool struct {
	agents []*agentEntry
	rr     uint32
}

type agentEntry struct {
	id        string
	sess      transport.Session
	services  map[string]control.Service
	healthy   atomic.Bool
	tunActive map[string]struct{}
	mu        sync.Mutex
	rtt       atomic.Int64
}

func New(cfg *config.Config) *Gateway {
	svcByName := make(map[string]config.Service)
	svcLimits := make(map[string]*mux.Limiter)
	svcACL := make(map[string][]*net.IPNet)
	for _, svc := range cfg.Services {
		svcByName[svc.Name] = svc
		if svc.MaxStreams > 0 {
			svcLimits[svc.Name] = mux.NewLimiter(svc.MaxStreams)
		}
		if len(svc.AllowCIDRs) > 0 {
			nets := make([]*net.IPNet, 0, len(svc.AllowCIDRs))
			for _, cidr := range svc.AllowCIDRs {
				_, n, err := net.ParseCIDR(cidr)
				if err == nil && n != nil {
					nets = append(nets, n)
				}
			}
			if len(nets) > 0 {
				svcACL[svc.Name] = nets
			}
		}
	}
	return &Gateway{
		cfg:        cfg,
		registry:   &registry{services: make(map[string]*servicePool)},
		svcByName:  svcByName,
		limiter:    mux.NewLimiter(cfg.Mux.MaxStreamsTotal),
		svcLimits:  svcLimits,
		svcACL:     svcACL,
		acceptKeys: cfg.AcceptedSharedKeys(),
		writeKey:   cfg.ActiveSharedKey(),
		replay:     newReplayFilter(cfg),
	}
}

func (g *Gateway) Start(ctx context.Context) error {
	metrics.Start(g.cfg.Metrics.Listen, g.cfg.Metrics.AuthToken, g.cfg.Metrics.Pprof)

	if g.cfg.WARP.Enabled {
		if err := g.startWARP(ctx); err != nil {
			log.Printf("WARP tunnel start failed: %v", err)
		}
	}

	g.startNoizeTelemetry(ctx)
	listener, err := g.buildListener()
	if err != nil {
		return err
	}
	defer listener.Close()

	for _, svc := range g.cfg.Services {
		svc := svc
		switch defaultProto(svc.Protocol) {
		case "tcp":
			if svc.Listen != "" {
				go g.listenTCP(ctx, &svc)
			}
		case "udp":
			if svc.Listen != "" {
				go g.listenUDP(ctx, &svc)
			}
		case "socks5":
			if svc.Listen != "" {
				go g.listenSOCKS5(ctx, &svc)
			}
		case "tun":
			// handled when agent registers
		default:
			log.Printf("unsupported protocol %s for service %s", svc.Protocol, svc.Name)
		}
	}

	variantInfo := ""
	if g.cfg.Transport.Type == "uqsp" {
		variantInfo = fmt.Sprintf(" variant=%s", g.cfg.VariantName())
	}
	log.Printf("gateway listening on %s (%s%s)", g.cfg.Gateway.Listen, g.cfg.Transport.Type, variantInfo)
	transportLabel := g.cfg.Transport.Type
	if g.cfg.Transport.Type == "stealth" {
		transportLabel = stealthtx.MetricsLabel(g.cfg)
	}
	for {
		sess, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		sess = mux.WrapSession(sess, g.limiter)
		sess = mux.WrapSession(sess, mux.NewLimiter(g.cfg.Mux.MaxStreamsPerSession))
		metrics.IncSessions()
		metrics.IncTransportSession(transportLabel)
		go g.handleSession(ctx, sess)
	}
}

func (g *Gateway) startNoizeTelemetry(ctx context.Context) {
	noizeCfg := g.cfg.Transport.Stealth.Shaping.Noize
	if !noizeCfg.Enabled {
		return
	}
	n := noize.New(noize.Config{
		Enabled:          noizeCfg.Enabled,
		Preset:           noizeCfg.Preset,
		JunkInterval:     noizeCfg.JunkInterval,
		JunkMinSize:      noizeCfg.JunkMinSize,
		JunkMaxSize:      noizeCfg.JunkMaxSize,
		SignaturePackets: append([]string(nil), noizeCfg.SignaturePackets...),
		FragmentPackets:  noizeCfg.FragmentPackets,
		BurstPackets:     noizeCfg.BurstPackets,
		BurstInterval:    noizeCfg.BurstInterval,
		MaxJunkPercent:   noizeCfg.MaxJunkPercent,
		Adaptive:         noizeCfg.Adaptive,
	})
	n.Start(func(pkt []byte) error {
		metrics.IncObfsJunkPackets(1)
		if len(noizeCfg.SignaturePackets) > 0 {
			metrics.IncObfsSignaturePackets(1)
		}
		metrics.AddTrafficOutbound(int64(len(pkt)))
		return nil
	})
	go func() {
		<-ctx.Done()
		n.Stop()
	}()
}

func (g *Gateway) startWARP(ctx context.Context) error {
	warpCfg := g.cfg.WARP
	tunnel, err := warp.NewTunnel(warpCfg)
	if err != nil {
		return fmt.Errorf("create WARP tunnel: %w", err)
	}

	if err := tunnel.Start(); err != nil {
		return fmt.Errorf("start WARP tunnel: %w", err)
	}

	go func() {
		<-ctx.Done()
		tunnel.Close()
	}()

	log.Printf("WARP tunnel started (mode=%s, routing=%s)", warpCfg.Mode, warpCfg.RoutingMode)
	return nil
}

func (g *Gateway) buildListener() (transport.Listener, error) {
	switch g.cfg.Transport.Type {
	case "stealth":
		smuxCfg := stealthtx.BuildSessionConfig(g.cfg)
		l, _, err := stealthtx.BuildGatewayListener(g.cfg, smuxCfg)
		if err != nil {
			return nil, err
		}
		return l, nil

	case "uqsp":
		return g.buildUQSPListener()

	default:
		return nil, fmt.Errorf("transport.type=%s has been removed; use transport.type=stealth or transport.type=uqsp", g.cfg.Transport.Type)
	}
}

func (g *Gateway) buildUQSPListener() (transport.Listener, error) {
	// Build TLS config for QUIC
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{}, // Will be filled from config
	}

	// Load certificate if configured
	if g.cfg.Transport.TLS.CertFile != "" && g.cfg.Transport.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(g.cfg.Transport.TLS.CertFile, g.cfg.Transport.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}

	// Build smux config
	smuxCfg := smux.DefaultConfig()
	smuxCfg.MaxReceiveBuffer = g.cfg.Mux.MaxReceiveBuffer
	smuxCfg.MaxStreamBuffer = g.cfg.Mux.MaxStreamBuffer
	if d, err := time.ParseDuration(g.cfg.Mux.SmuxKeepAliveInterval); err == nil {
		smuxCfg.KeepAliveInterval = d
	}
	if d, err := time.ParseDuration(g.cfg.Mux.SmuxKeepAliveTimeout); err == nil {
		smuxCfg.KeepAliveTimeout = d
	}

	if g.cfg.UQSPRuntimeMode() == "legacy" {
		log.Printf("UQSP runtime mode=legacy; using historical listener path")
		listener, err := uqsp.NewListener(
			g.cfg.Gateway.Listen, &g.cfg.Transport.UQSP, tlsCfg, smuxCfg, g.cfg.ActiveSharedKey())
		if err != nil {
			return nil, fmt.Errorf("create legacy UQSP listener: %w", err)
		}
		return listener, nil
	}

	// Use the unified runtime listener which routes through
	// BuildVariantForRole -> UnifiedProtocol with full variant overlay
	// chain, WARP egress, and reverse-initiation support.
	rl, err := uqsp.NewRuntimeListener(
		g.cfg.Gateway.Listen, g.cfg, tlsCfg, smuxCfg, g.cfg.ActiveSharedKey())
	if err != nil {
		return nil, fmt.Errorf("UQSP runtime listener: %w", err)
	}

	return rl, nil
}

func (g *Gateway) handleSession(ctx context.Context, sess transport.Session) {
	defer sess.Close()
	defer metrics.DecSessions()
	transportLabel := g.cfg.Transport.Type
	if g.cfg.Transport.Type == "stealth" {
		transportLabel = stealthtx.MetricsLabel(g.cfg)
	}
	defer metrics.DecTransportSession(transportLabel)
	strm, err := sess.AcceptStream()
	if err != nil {
		log.Printf("control accept failed: %v", err)
		metrics.IncErrors()
		return
	}
	defer strm.Close()
	env, _, err := control.ReadEnvelopeWithDeadlineAnyKey(strm, g.cfg.HeaderTimeout(), g.acceptKeys, control.DefaultConfig())
	if err != nil {
		log.Printf("control read failed: %v", err)
		metrics.IncErrors()
		return
	}
	if env.Type != control.TypeHello || env.Hello == nil {
		log.Printf("invalid hello")
		metrics.IncErrors()
		return
	}
	if g.isReplay(env.Hello.AgentID, env.Type, env.Nonce) {
		log.Printf("replay detected on hello from %s", env.Hello.AgentID)
		metrics.IncErrors()
		return
	}
	if !g.authorizeAgentHello(env.Hello.AgentID, env.Hello.SharedKey) {
		log.Printf("agent auth failed for %s", env.Hello.AgentID)
		metrics.IncErrors()
		return
	}

	entry := &agentEntry{
		id:        env.Hello.AgentID,
		sess:      sess,
		services:  make(map[string]control.Service),
		tunActive: make(map[string]struct{}),
	}
	entry.healthy.Store(true)
	allowed := g.allowedServiceSet(env.Hello.AgentID)
	for _, svc := range env.Hello.Services {
		if len(allowed) > 0 {
			if _, ok := allowed[svc.Name]; !ok {
				continue
			}
		}
		entry.services[svc.Name] = svc
		g.registry.register(svc.Name, entry)
		if defaultProto(svc.Protocol) == "tun" {
			go g.startTun(ctx, entry, svc.Name)
		}
	}
	log.Printf("agent %s registered %d services", entry.id, len(entry.services))

	go g.pingLoop(entry)

	// Drain any unexpected inbound streams.
	for {
		strm, err := sess.AcceptStream()
		if err != nil {
			break
		}
		metrics.IncStreams()
		_ = strm.Close()
		metrics.DecStreams()
	}

	entry.healthy.Store(false)
	g.registry.unregisterAgent(entry)
	log.Printf("agent %s disconnected", entry.id)
}

func (g *Gateway) pingLoop(entry *agentEntry) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		if !entry.healthy.Load() {
			return
		}
		if err := g.pingAgent(entry); err != nil {
			log.Printf("agent %s health check failed: %v", entry.id, err)
			entry.healthy.Store(false)
			_ = entry.sess.Close()
			return
		}
		<-ticker.C
	}
}

func (g *Gateway) pingAgent(entry *agentEntry) error {
	strm, err := entry.sess.OpenStream()
	if err != nil {
		return err
	}
	defer strm.Close()
	env := &control.Envelope{Type: control.TypePing, Ping: &control.Ping{Timestamp: time.Now().UnixNano()}}
	if err := control.WriteEnvelopeWithDeadline(strm, pingTimeout, env, g.writeKey); err != nil {
		return err
	}
	resp, _, err := control.ReadEnvelopeWithDeadlineAnyKey(strm, pingTimeout, g.acceptKeys, control.DefaultConfig())
	if err != nil {
		return err
	}
	if g.isReplay(entry.id, resp.Type, resp.Nonce) {
		return fmt.Errorf("replay detected in ping response")
	}
	if resp.Type != control.TypePong {
		return fmt.Errorf("unexpected ping response: %s", resp.Type)
	}
	rtt := time.Since(time.Unix(0, env.Ping.Timestamp))
	metrics.SetPingRTT(rtt)
	entry.rtt.Store(rtt.Milliseconds())
	return nil
}

func (g *Gateway) listenTCP(ctx context.Context, svc *config.Service) {
	ln, err := net.Listen("tcp", svc.Listen)
	if err != nil {
		log.Printf("service %s listen failed: %v", svc.Name, err)
		return
	}
	defer ln.Close()
	log.Printf("service %s listening on %s (tcp)", svc.Name, svc.Listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("accept error on %s: %v", svc.Name, err)
				continue
			}
		}
		go g.handleTCP(ctx, svc, conn)
	}
}

func (g *Gateway) handleTCP(ctx context.Context, svc *config.Service, conn net.Conn) {
	defer conn.Close()
	netutil.ApplyTCPRuntimeOptions(conn, g.cfg.Transport.Stealth.Performance.TCP)
	if !g.allowed(svc.Name, conn.RemoteAddr()) {
		log.Printf("service %s denied remote %s", svc.Name, conn.RemoteAddr())
		metrics.IncErrors()
		return
	}
	releaseSvc := g.acquireSvc(svc.Name)
	if releaseSvc == nil {
		log.Printf("service %s stream limit reached", svc.Name)
		metrics.IncErrors()
		return
	}
	entry := g.registry.pick(svc.Name)
	if entry == nil {
		log.Printf("no agent for service %s", svc.Name)
		metrics.IncErrors()
		releaseSvc()
		return
	}
	strm, err := entry.sess.OpenStream()
	if err != nil {
		log.Printf("open stream failed: %v", err)
		metrics.IncErrors()
		releaseSvc()
		return
	}
	defer strm.Close()
	metrics.IncStreams()
	metrics.IncService(svc.Name)
	defer func() {
		metrics.DecStreams()
		metrics.DecService(svc.Name)
		releaseSvc()
	}()

	env := &control.Envelope{Type: control.TypeOpen, Open: &control.Open{ServiceName: svc.Name, Protocol: "tcp"}}
	if err := control.WriteEnvelopeWithDeadline(strm, 5*time.Second, env, g.writeKey); err != nil {
		log.Printf("write open failed: %v", err)
		metrics.IncErrors()
		return
	}

	if err := relay.PipeCounted(conn, strm, metrics.AddTrafficInbound, metrics.AddTrafficOutbound); err != nil {
		log.Printf("relay error for service %s: %v", svc.Name, err)
	}
}

func (g *Gateway) listenUDP(ctx context.Context, svc *config.Service) {
	laddr, err := net.ResolveUDPAddr("udp", svc.Listen)
	if err != nil {
		log.Printf("udp resolve failed for %s: %v", svc.Name, err)
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Printf("udp listen failed for %s: %v", svc.Name, err)
		return
	}
	defer conn.Close()
	if svc.UDP.ReadBuffer > 0 {
		_ = conn.SetReadBuffer(svc.UDP.ReadBuffer)
	}
	if svc.UDP.WriteBuffer > 0 {
		_ = conn.SetWriteBuffer(svc.UDP.WriteBuffer)
	}
	log.Printf("service %s listening on %s (udp)", svc.Name, svc.Listen)

	sessions := make(map[string]*udpSession)
	var mu sync.Mutex
	limiterIn := ratelimit.New(svc.UDP.MaxBPS, svc.UDP.MaxPPS, svc.UDP.Burst, svc.UDP.Mode)
	limiterOut := ratelimit.New(svc.UDP.MaxBPS, svc.UDP.MaxPPS, svc.UDP.Burst, svc.UDP.Mode)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				for key, us := range sessions {
					if time.Since(us.lastSeen) > udpIdleTimeout {
						_ = us.stream.Close()
						if us.release != nil {
							us.release()
						}
						delete(sessions, key)
					}
				}
				metrics.SetUDPSessions(int64(len(sessions)))
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("udp read error on %s: %v", svc.Name, err)
				continue
			}
		}
		if !limiterIn.Allow(n) {
			continue
		}
		if !g.allowed(svc.Name, addr) {
			continue
		}
		key := addr.String()

		mu.Lock()
		us := sessions[key]
		if us == nil {
			entry := g.registry.pick(svc.Name)
			if entry == nil {
				mu.Unlock()
				log.Printf("no agent for service %s", svc.Name)
				continue
			}
			strm, err := entry.sess.OpenStream()
			if err != nil {
				mu.Unlock()
				log.Printf("udp open stream failed: %v", err)
				if release := g.acquireSvc(svc.Name); release != nil {
					release() // release immediately since stream not created
				}
				continue
			}
			releaseSvc := g.acquireSvc(svc.Name)
			if releaseSvc == nil {
				mu.Unlock()
				_ = strm.Close()
				log.Printf("service %s stream limit reached", svc.Name)
				continue
			}
			env := &control.Envelope{Type: control.TypeOpen, Open: &control.Open{ServiceName: svc.Name, Protocol: "udp"}}
			if err := control.WriteEnvelopeWithDeadline(strm, 5*time.Second, env, g.writeKey); err != nil {
				mu.Unlock()
				_ = strm.Close()
				releaseSvc()
				log.Printf("udp write open failed: %v", err)
				continue
			}
			us = &udpSession{stream: strm, client: addr, lastSeen: time.Now(), release: releaseSvc, service: svc.Name}
			metrics.IncStreams()
			metrics.IncService(svc.Name)
			sessions[key] = us
			metrics.SetUDPSessions(int64(len(sessions)))
			go g.udpReadLoop(ctx, conn, us, key, &mu, sessions, limiterOut, releaseSvc)
		}
		us.lastSeen = time.Now()
		mu.Unlock()

		if err := relay.WriteFrame(us.stream, buf[:n]); err != nil {
			log.Printf("udp forward error: %v", err)
			metrics.IncErrors()
			mu.Lock()
			_ = us.stream.Close()
			if us.release != nil {
				us.release()
			}
			if us.service != "" {
				metrics.DecService(us.service)
			}
			delete(sessions, key)
			metrics.SetUDPSessions(int64(len(sessions)))
			metrics.DecStreams()
			mu.Unlock()
		} else {
			metrics.AddTrafficInbound(int64(n))
		}
	}
}

type udpSession struct {
	stream   net.Conn
	client   *net.UDPAddr
	lastSeen time.Time
	release  func()
	service  string
}

func (g *Gateway) udpReadLoop(ctx context.Context, conn *net.UDPConn, us *udpSession, key string, mu *sync.Mutex, sessions map[string]*udpSession, limiter *ratelimit.Limiter, releaseSvc func()) {
	for {
		pkt, err := relay.ReadFrame(us.stream)
		if err != nil {
			mu.Lock()
			delete(sessions, key)
			metrics.SetUDPSessions(int64(len(sessions)))
			mu.Unlock()
			_ = us.stream.Close()
			metrics.DecStreams()
			if us.service != "" {
				metrics.DecService(us.service)
			}
			if releaseSvc != nil {
				releaseSvc()
			}
			return
		}
		if !limiter.Allow(len(pkt)) {
			continue
		}
		if n, err := conn.WriteToUDP(pkt, us.client); err == nil {
			metrics.AddTrafficOutbound(int64(n))
		}
	}
}

func (g *Gateway) startTun(ctx context.Context, entry *agentEntry, name string) {
	svc, ok := g.svcByName[name]
	if !ok || defaultProto(svc.Protocol) != "tun" {
		return
	}
	releaseSvc := g.acquireSvc(name)
	if releaseSvc == nil {
		log.Printf("tun service %s stream limit reached", name)
		return
	}
	entry.mu.Lock()
	if _, exists := entry.tunActive[name]; exists {
		entry.mu.Unlock()
		releaseSvc()
		return
	}
	entry.tunActive[name] = struct{}{}
	entry.mu.Unlock()
	defer func() {
		entry.mu.Lock()
		delete(entry.tunActive, name)
		entry.mu.Unlock()
	}()

	strm, err := entry.sess.OpenStream()
	if err != nil {
		log.Printf("tun open stream failed: %v", err)
		releaseSvc()
		return
	}
	metrics.IncStreams()
	metrics.IncService(name)
	defer releaseSvc()
	env := &control.Envelope{Type: control.TypeOpen, Open: &control.Open{ServiceName: name, Protocol: "tun"}}
	if err := control.WriteEnvelopeWithDeadline(strm, 5*time.Second, env, g.writeKey); err != nil {
		_ = strm.Close()
		metrics.DecStreams()
		log.Printf("tun write open failed: %v", err)
		return
	}
	if g.cfg.VPN.Enabled {
		vpnCfg := g.cfg.VPN
		if vpnCfg.Name == "" {
			vpnCfg.Name = svc.Tun.Name
		}
		if vpnCfg.MTU <= 0 && svc.Tun.MTU > 0 {
			vpnCfg.MTU = svc.Tun.MTU
		}
		if vpnCfg.Mode == "" {
			vpnCfg.Mode = svc.Tun.Mode
		}
		if vpnCfg.Mode == "" {
			vpnCfg.Mode = "tun"
		}

		session, err := vpn.NewSession(vpnCfg, strm)
		if err != nil {
			_ = strm.Close()
			metrics.DecStreams()
			log.Printf("vpn session init failed: %v", err)
			return
		}
		errCh := make(chan error, 1)
		session.SetErrorHandler(func(err error) {
			select {
			case errCh <- err:
			default:
			}
		})
		if err := session.Start(); err != nil {
			_ = strm.Close()
			metrics.DecStreams()
			log.Printf("vpn session start failed: %v", err)
			_ = session.Close()
			return
		}

		log.Printf("tun service %s started on %s (vpn mode)", name, session.InterfaceName())
		select {
		case <-ctx.Done():
		case err := <-errCh:
			if err != nil {
				log.Printf("tun service %s ended: %v", name, err)
			}
		}
		_ = session.Close()
		metrics.DecStreams()
		metrics.DecService(name)
		releaseSvc()
		return
	}

	iface, err := tun.OpenWithMode(tun.Config{
		Name: svc.Tun.Name,
		MTU:  svc.Tun.MTU,
		Mode: svc.Tun.Mode,
	})
	if err != nil {
		_ = strm.Close()
		metrics.DecStreams()
		log.Printf("tun open failed: %v", err)
		return
	}
	log.Printf("tun service %s started on %s", name, iface.Name())
	if err := tun.Bridge(ctx, iface, strm); err != nil {
		log.Printf("tun service %s ended: %v", name, err)
	}
	metrics.DecStreams()
	metrics.DecService(name)
	releaseSvc()
}

func (r *registry) register(name string, entry *agentEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pool := r.services[name]
	if pool == nil {
		pool = &servicePool{}
		r.services[name] = pool
	}
	pool.agents = append(pool.agents, entry)
}

func (r *registry) unregisterAgent(entry *agentEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, pool := range r.services {
		filtered := pool.agents[:0]
		for _, e := range pool.agents {
			if e != entry {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			delete(r.services, name)
			continue
		}
		pool.agents = filtered
	}
}

func (r *registry) pick(name string) *agentEntry {
	r.mu.RLock()
	pool := r.services[name]
	r.mu.RUnlock()
	if pool == nil || len(pool.agents) == 0 {
		return nil
	}
	var best *agentEntry
	var bestRTT int64 = -1
	for _, e := range pool.agents {
		if !e.healthy.Load() {
			continue
		}
		rtt := e.rtt.Load()
		if rtt <= 0 {
			// unknown rtt; keep for fallback
			if best == nil {
				best = e
			}
			continue
		}
		if bestRTT == -1 || rtt < bestRTT {
			bestRTT = rtt
			best = e
		}
	}
	if best != nil {
		return best
	}
	// fallback to round-robin among all
	for i := 0; i < len(pool.agents); i++ {
		idx := int(atomic.AddUint32(&pool.rr, 1)) % len(pool.agents)
		e := pool.agents[idx]
		if e.healthy.Load() {
			return e
		}
	}
	return nil
}

func (r *registry) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return fmt.Sprintf("%d services", len(r.services))
}

func defaultProto(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}

func newReplayFilter(cfg *config.Config) *bloom.Filter {
	if !cfg.Security.ReplayProtect {
		return nil
	}
	capacity := cfg.Security.ReplayCapacity
	if capacity <= 0 {
		capacity = 1000000
	}
	return bloom.New(uint64(capacity), 1e-6)
}

func (g *Gateway) isReplay(agentID, typ, nonce string) bool {
	if g.replay == nil {
		return false
	}
	return g.replay.CheckAndAdd(control.EncodeReplayKey(agentID, typ, nonce))
}

func (g *Gateway) authorizeAgentHello(agentID, token string) bool {
	return authn.AuthorizeAgent(g.cfg, agentID, token)
}

func (g *Gateway) allowedServiceSet(agentID string) map[string]struct{} {
	if len(g.cfg.Security.AgentServices) == 0 {
		return nil
	}
	names := g.cfg.Security.AgentServices[agentID]
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

// allowed checks if remote address is within allow_cidrs for the service; allow all if unset.
func (g *Gateway) allowed(service string, addr net.Addr) bool {
	acls := g.svcACL[service]
	if len(acls) == 0 {
		return true
	}
	var ip net.IP
	switch v := addr.(type) {
	case *net.TCPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil {
		return false
	}
	for _, n := range acls {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// acquireSvc tries to reserve one stream slot for a service, enforcing max_streams when configured.
// It returns a release function; nil means limit exceeded.
func (g *Gateway) acquireSvc(name string) func() {
	lim := g.svcLimits[name]
	if lim == nil {
		return func() {}
	}
	if !lim.TryAcquire() {
		return nil
	}
	return func() { lim.Release() }
}

func (g *Gateway) listenSOCKS5(ctx context.Context, svc *config.Service) {
	srv := &socks5.Server{
		Username: svc.SOCKS5.Username,
		Password: svc.SOCKS5.Password,
		Dial: func(dialCtx context.Context, protocol, address string) (net.Conn, error) {
			if !g.allowed(svc.Name, &net.TCPAddr{IP: net.IPv4zero}) {
				return nil, fmt.Errorf("service %s access denied", svc.Name)
			}
			releaseSvc := g.acquireSvc(svc.Name)
			if releaseSvc == nil {
				return nil, fmt.Errorf("service %s stream limit reached", svc.Name)
			}
			entry := g.registry.pick(svc.Name)
			if entry == nil {
				releaseSvc()
				return nil, fmt.Errorf("no agent for service %s", svc.Name)
			}
			strm, err := entry.sess.OpenStream()
			if err != nil {
				releaseSvc()
				return nil, err
			}
			metrics.IncStreams()
			metrics.IncService(svc.Name)

			env := &control.Envelope{
				Type: control.TypeOpen,
				Open: &control.Open{
					ServiceName: svc.Name,
					Protocol:    protocol,
					Target:      address,
				},
			}
			if err := control.WriteEnvelopeWithDeadline(strm, 5*time.Second, env, g.writeKey); err != nil {
				strm.Close()
				metrics.DecStreams()
				metrics.DecService(svc.Name)
				releaseSvc()
				return nil, err
			}

			return &socksStreamConn{
				Conn:       strm,
				releaseSvc: releaseSvc,
				svcName:    svc.Name,
			}, nil
		},
	}
	if err := srv.ListenAndServe(ctx, svc.Listen); err != nil {
		log.Printf("socks5 service %s error: %v", svc.Name, err)
	}
}

// socksStreamConn wraps a stream connection with cleanup on close.
type socksStreamConn struct {
	net.Conn
	releaseSvc func()
	svcName    string
	closed     atomic.Bool
}

func (c *socksStreamConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		metrics.DecStreams()
		metrics.DecService(c.svcName)
		if c.releaseSvc != nil {
			c.releaseSvc()
		}
	}
	return c.Conn.Close()
}
