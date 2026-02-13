package carrier

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/anytls"

	"github.com/xtaci/smux"
)

// AnyTLSCarrier implements AnyTLS as a UQSP carrier.
type AnyTLSCarrier struct {
	config  config.AnyTLSCarrierConfig
	smuxCfg *smux.Config
	dialer  *anytls.Dialer
}

// NewAnyTLSCarrier creates a new AnyTLS carrier.
func NewAnyTLSCarrier(cfg config.AnyTLSCarrierConfig, smuxCfg *smux.Config) (*AnyTLSCarrier, error) {
	anyCfg := &anytls.Config{
		Padding: anytls.PaddingConfig{
			Scheme: cfg.PaddingScheme,
			Min:    cfg.PaddingMin,
			Max:    cfg.PaddingMax,
			Lines:  cfg.PaddingLines,
		},
		IdleSessionTimeout: time.Duration(cfg.IdleSessionTimeout) * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			ServerName:         cfg.TLSServerName,
			MinVersion:         tls.VersionTLS13,
		},
		Password: cfg.Password,
	}

	d, err := anytls.NewDialer(anyCfg, smuxCfg, "", cfg.Server) // Guard handled at session layer
	if err != nil {
		return nil, err
	}

	return &AnyTLSCarrier{
		config:  cfg,
		smuxCfg: smuxCfg,
		dialer:  d,
	}, nil
}

// Network returns the network type.
func (c *AnyTLSCarrier) Network() string {
	return "tcp"
}

// Dial connects to the AnyTLS server.
func (c *AnyTLSCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if c.dialer == nil {
		return nil, fmt.Errorf("anytls dialer not initialized")
	}
	// We need to pass the target address to the AnyTLS dialer if it doesn't have it.
	// Actually, our anytls.Dialer.Dial(ctx, addr) returns a Session.
	sess, err := c.dialer.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	
	// Open the first stream to use as the carrier connection
	return sess.OpenStream()
}

// Listen creates an AnyTLS listener.
func (c *AnyTLSCarrier) Listen(addr string) (Listener, error) {
	anyCfg := &anytls.Config{
		Padding: anytls.PaddingConfig{
			Scheme: c.config.PaddingScheme,
			Min:    c.config.PaddingMin,
			Max:    c.config.PaddingMax,
			Lines:  c.config.PaddingLines,
		},
		IdleSessionTimeout: time.Duration(c.config.IdleSessionTimeout) * time.Second,
	}

	l, err := anytls.Listen(addr, anyCfg, c.smuxCfg, "")
	if err != nil {
		return nil, err
	}
	
	return &anytlsListenerWrapper{l}, nil
}

// Close closes the carrier.
func (c *AnyTLSCarrier) Close() error {
	return nil
}

// IsAvailable returns true if AnyTLS is available.
func (c *AnyTLSCarrier) IsAvailable() bool {
	return true
}

type anytlsListenerWrapper struct {
	*anytls.Listener
}

func (w *anytlsListenerWrapper) Accept() (net.Conn, error) {
	sess, err := w.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return sess.AcceptStream()
}

func (w *anytlsListenerWrapper) Close() error {
	return w.Listener.Close()
}

func (w *anytlsListenerWrapper) Addr() net.Addr {
	return w.Listener.Addr()
}
