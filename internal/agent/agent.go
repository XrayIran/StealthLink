package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/control"
	"stealthlink/internal/metrics"
	"stealthlink/internal/mux"
	"stealthlink/internal/netutil"
	"stealthlink/internal/ratelimit"
	"stealthlink/internal/relay"
	"stealthlink/internal/security/bloom"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/noize"
	stealthtx "stealthlink/internal/transport/stealth"
	"stealthlink/internal/transport/tfo"
	"stealthlink/internal/transport/uqsp"
	"stealthlink/internal/tun"

	"github.com/xtaci/smux"
)

func jitterBackoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 3 * time.Second
	}
	if attempt < 0 {
		attempt = 0
	}
	d := base
	for i := 0; i < attempt && d < 60*time.Second; i++ {
		d = time.Duration(float64(d) * 1.6)
		if d > 60*time.Second {
			d = 60 * time.Second
			break
		}
	}
	jitter := d / 2
	return d - jitter/2 + time.Duration(time.Now().UnixNano()%int64(jitter))
}

type Agent struct {
	cfg        *config.Config
	tunMu      sync.Mutex
	tunActive  map[string]struct{}
	limiter    *mux.Limiter
	acceptKeys []string
	writeKey   string
	replay     *bloom.Filter
}

func New(cfg *config.Config) *Agent {
	return &Agent{
		cfg:        cfg,
		tunActive:  make(map[string]struct{}),
		limiter:    mux.NewLimiter(cfg.Mux.MaxStreamsTotal),
		acceptKeys: cfg.AcceptedSharedKeys(),
		writeKey:   cfg.ActiveSharedKey(),
		replay:     newReplayFilter(cfg),
	}
}

func (a *Agent) Start(ctx context.Context) error {
	metrics.Start(a.cfg.Metrics.Listen, a.cfg.Metrics.AuthToken)
	a.startNoizeTelemetry(ctx)
	groups := groupServices(a.cfg)
	for key, grp := range groups {
		key := key
		maxConns := key.maxConns
		if a.cfg.Transport.Type == "stealth" && stealthtx.IsHTTPProfile(a.cfg.StealthCamouflageProfile()) && maxConns <= 0 {
			maxConns = a.cfg.Transport.Stealth.Camouflage.HTTPCover.MaxConnections
		}
		if maxConns <= 0 || !stealthtx.IsHTTPProfile(a.cfg.StealthCamouflageProfile()) {
			maxConns = 1
		}
		for i := 0; i < maxConns; i++ {
			go a.runGroupLoop(ctx, key, grp)
		}
	}
	<-ctx.Done()
	return nil
}

func (a *Agent) startNoizeTelemetry(ctx context.Context) {
	noizeCfg := a.cfg.Transport.Stealth.Shaping.Noize
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

func (a *Agent) runGroupLoop(ctx context.Context, key hostKey, grp serviceGroup) {
	attempt := 0
	for {
		err := a.runGroupOnce(ctx, key, grp)
		if err != nil {
			log.Printf("agent session ended (host=%s): %v", key.host, err)
			metrics.IncErrors()
			attempt++
		} else {
			attempt = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitterBackoff(a.cfg.ReconnectBackoff(), attempt)):
		}
	}
}

func (a *Agent) runGroupOnce(ctx context.Context, key hostKey, grp serviceGroup) error {
	dialer, addr, err := a.buildDialer(key, grp.headers)
	if err != nil {
		return err
	}

	sess, err := dialer.Dial(ctx, addr)
	if err != nil {
		return err
	}
	sess = mux.WrapSession(sess, a.limiter)
	sess = mux.WrapSession(sess, mux.NewLimiter(a.cfg.Mux.MaxStreamsPerSession))
	defer sess.Close()
	metrics.IncSessions()
	defer metrics.DecSessions()
	transportLabel := a.cfg.Transport.Type
	if a.cfg.Transport.Type == "stealth" {
		transportLabel = stealthtx.MetricsLabel(a.cfg)
	}
	metrics.IncTransportSession(transportLabel)
	defer metrics.DecTransportSession(transportLabel)

	if err := a.sendHello(sess, grp.services); err != nil {
		return err
	}
	return a.acceptStreams(ctx, sess)
}

func (a *Agent) buildDialer(key hostKey, headers map[string]string) (transport.Dialer, string, error) {
	smuxCfg := stealthtx.BuildSessionConfig(a.cfg)
	target := buildTarget(a.cfg, key, headers)
	proxyDial := transport.ProxyDialerWithTFO(a.cfg.Transport.Proxy.URL, tfo.Config{
		Enabled:   a.cfg.Transport.Stealth.Performance.TFO.Enabled,
		QueueSize: a.cfg.Transport.Stealth.Performance.TFO.QueueSize,
	})
	return a.buildDialerForType(a.cfg.Transport.Type, target, smuxCfg, proxyDial)
}

func (a *Agent) buildDialerForType(transportType string, target transportTarget, smuxCfg *smux.Config, proxyDial func(ctx context.Context, network, addr string) (net.Conn, error)) (transport.Dialer, string, error) {
	switch transportType {
	case "stealth":
		d, addr, _, err := stealthtx.BuildAgentDialer(a.cfg, stealthtx.Target{
			Addr:        target.addr,
			Host:        target.host,
			SNI:         target.sni,
			Origin:      target.origin,
			Path:        target.path,
			Fingerprint: target.fingerprint,
			Headers:     target.headers,
		}, smuxCfg, proxyDial)
		if err != nil {
			return nil, "", err
		}
		return d, addr, nil

	case "uqsp":
		return a.buildUQSPDialer(target)

	default:
		return nil, "", configLegacyTransportError(transportType)
	}
}

func (a *Agent) buildUQSPDialer(target transportTarget) (transport.Dialer, string, error) {
	tlsCfg := &tls.Config{
		ServerName:         a.cfg.Transport.TLS.ServerName,
		InsecureSkipVerify: a.cfg.Transport.TLS.InsecureSkipVerify,
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.MaxReceiveBuffer = a.cfg.Mux.MaxReceiveBuffer
	smuxCfg.MaxStreamBuffer = a.cfg.Mux.MaxStreamBuffer
	if d, err := time.ParseDuration(a.cfg.Mux.SmuxKeepAliveInterval); err == nil {
		smuxCfg.KeepAliveInterval = d
	}
	if d, err := time.ParseDuration(a.cfg.Mux.SmuxKeepAliveTimeout); err == nil {
		smuxCfg.KeepAliveTimeout = d
	}

	log.Printf("UQSP connecting with variant=%s: %s", a.cfg.VariantName(), a.cfg.VariantDescription())

	dialer := uqsp.NewDialer(&a.cfg.Transport.UQSP, tlsCfg, smuxCfg, a.cfg.AgentToken(a.cfg.Agent.ID))

	return dialer, a.cfg.Agent.GatewayAddr, nil
}

func configLegacyTransportError(transportType string) error {
	return fmt.Errorf("transport.type=%s has been removed; use transport.type=stealth with transport.stealth.{carrier,camouflage,shaping,selection,performance,security,session}", transportType)
}

func (a *Agent) sendHello(sess transport.Session, svcs []*config.Service) error {
	strm, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer strm.Close()

	services := make([]control.Service, 0, len(svcs))
	for _, svc := range svcs {
		services = append(services, control.Service{
			Name:     svc.Name,
			Protocol: defaultProto(svc.Protocol),
			Target:   svc.Target,
		})
	}
	env := &control.Envelope{
		Type: control.TypeHello,
		Hello: &control.Hello{
			AgentID:   a.cfg.Agent.ID,
			Services:  services,
			SharedKey: a.cfg.AgentToken(a.cfg.Agent.ID),
		},
	}
	return control.WriteEnvelopeWithDeadline(strm, 5*time.Second, env, a.writeKey)
}

func (a *Agent) acceptStreams(ctx context.Context, sess transport.Session) error {
	for {
		strm, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		metrics.IncStreams()
		go func() {
			defer metrics.DecStreams()
			a.handleStream(ctx, strm)
		}()
	}
}

func (a *Agent) handleStream(ctx context.Context, strm net.Conn) {
	defer strm.Close()
	env, _, err := control.ReadEnvelopeWithDeadlineAnyKey(strm, a.cfg.HeaderTimeout(), a.acceptKeys, control.DefaultConfig())
	if err != nil {
		log.Printf("read open failed: %v", err)
		metrics.IncErrors()
		return
	}
	if a.isReplay(env.Type, env.Nonce) {
		log.Printf("replay detected for control message type=%s", env.Type)
		metrics.IncErrors()
		return
	}
	switch env.Type {
	case control.TypePing:
		resp := &control.Envelope{Type: control.TypePong, Pong: &control.Pong{Timestamp: time.Now().UnixNano()}}
		_ = control.WriteEnvelopeWithDeadline(strm, 5*time.Second, resp, a.writeKey)
		return
	case control.TypeOpen:
		// continue
	default:
		log.Printf("invalid stream type: %s", env.Type)
		metrics.IncErrors()
		return
	}
	if env.Open == nil {
		log.Printf("missing open payload")
		metrics.IncErrors()
		return
	}
	svc := a.findService(env.Open.ServiceName)
	if svc == nil {
		log.Printf("unknown service %s", env.Open.ServiceName)
		metrics.IncErrors()
		return
	}
	proto := defaultProto(env.Open.Protocol)
	// For socks5, use the dynamic target from the open envelope
	target := svc.Target
	if env.Open.Target != "" {
		target = env.Open.Target
	}
	switch proto {
	case "tcp":
		a.handleTCPTarget(strm, svc, target)
	case "udp":
		a.handleUDPTarget(strm, svc, target)
	case "tun":
		a.handleTun(ctx, strm, svc)
	default:
		log.Printf("protocol %s not supported", env.Open.Protocol)
		metrics.IncErrors()
	}
}

func (a *Agent) handleTCP(strm net.Conn, svc *config.Service) {
	a.handleTCPTarget(strm, svc, svc.Target)
}

func (a *Agent) handleTCPTarget(strm net.Conn, svc *config.Service, target string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("dial target failed: %v", err)
		metrics.IncErrors()
		return
	}
	defer conn.Close()
	netutil.ApplyTCPRuntimeOptions(conn, a.cfg.Transport.Stealth.Performance.TCP)
	netutil.ApplyTCPRuntimeOptions(strm, a.cfg.Transport.Stealth.Performance.TCP)
	if err := relay.PipeCounted(strm, conn, metrics.AddTrafficInbound, metrics.AddTrafficOutbound); err != nil {
		log.Printf("relay error: %v", err)
		metrics.IncErrors()
	}
}

func (a *Agent) handleUDP(strm net.Conn, svc *config.Service) {
	a.handleUDPTarget(strm, svc, svc.Target)
}

func (a *Agent) handleUDPTarget(strm net.Conn, svc *config.Service, target string) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("udp resolve failed: %v", err)
		metrics.IncErrors()
		return
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Printf("udp dial failed: %v", err)
		metrics.IncErrors()
		return
	}
	defer conn.Close()
	if svc.UDP.ReadBuffer > 0 {
		_ = conn.SetReadBuffer(svc.UDP.ReadBuffer)
	}
	if svc.UDP.WriteBuffer > 0 {
		_ = conn.SetWriteBuffer(svc.UDP.WriteBuffer)
	}

	limiter := ratelimit.New(svc.UDP.MaxBPS, svc.UDP.MaxPPS, svc.UDP.Burst, svc.UDP.Mode)

	errCh := make(chan error, 2)
	go func() {
		for {
			pkt, err := relay.ReadFrame(strm)
			if err != nil {
				errCh <- err
				return
			}
			if !limiter.Allow(len(pkt)) {
				continue
			}
			if _, err := conn.Write(pkt); err != nil {
				errCh <- err
				return
			}
			metrics.AddTrafficInbound(int64(len(pkt)))
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if !limiter.Allow(n) {
				continue
			}
			if err := relay.WriteFrame(strm, buf[:n]); err != nil {
				errCh <- err
				return
			}
			metrics.AddTrafficOutbound(int64(n))
		}
	}()
	<-errCh
}

func (a *Agent) handleTun(ctx context.Context, strm net.Conn, svc *config.Service) {
	a.tunMu.Lock()
	if _, exists := a.tunActive[svc.Name]; exists {
		a.tunMu.Unlock()
		log.Printf("tun service %s already active", svc.Name)
		return
	}
	a.tunActive[svc.Name] = struct{}{}
	a.tunMu.Unlock()

	iface, err := tun.Open(svc.Tun.Name, svc.Tun.MTU)
	if err != nil {
		log.Printf("tun open failed: %v", err)
		metrics.IncErrors()
		return
	}
	defer func() {
		_ = iface.Close()
		a.tunMu.Lock()
		delete(a.tunActive, svc.Name)
		a.tunMu.Unlock()
	}()

	log.Printf("tun service %s started on %s", svc.Name, iface.Name())
	if err := tun.Bridge(ctx, iface, strm); err != nil {
		log.Printf("tun service %s ended: %v", svc.Name, err)
		metrics.IncErrors()
	}
}

func (a *Agent) findService(name string) *config.Service {
	for i := range a.cfg.Services {
		svc := &a.cfg.Services[i]
		if svc.Name == name {
			return svc
		}
	}
	return nil
}

func defaultProto(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}

// buildURL moved to dialer.go

func newReplayFilter(cfg *config.Config) *bloom.Filter {
	if !cfg.Security.ReplayProtect {
		return nil
	}
	capacity := cfg.Security.ReplayCapacity
	if capacity <= 0 {
		capacity = 100000
	}
	return bloom.New(uint64(capacity), 1e-9)
}

func (a *Agent) isReplay(typ, nonce string) bool {
	if a.replay == nil {
		return false
	}
	return a.replay.CheckAndAdd(control.EncodeReplayKey(a.cfg.Agent.ID, typ, nonce))
}
