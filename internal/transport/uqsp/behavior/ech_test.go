package behavior

import (
	"context"
	"encoding/base64"
	"net"
	"testing"

	"stealthlink/internal/config"
	"stealthlink/internal/tlsutil"
)

func TestECHOverlayPrepareContextWithProvidedConfig(t *testing.T) {
	rawCfg := []byte{0x01, 0x02, 0x03, 0x04}
	overlay := NewECHOverlay(config.ECHBehaviorConfig{
		Enabled:    true,
		PublicName: "public.example",
		InnerSNI:   "inner.example",
		Configs:    []string{base64.StdEncoding.EncodeToString(rawCfg)},
		RequireECH: true,
	})

	ctx, err := overlay.PrepareContext(context.Background())
	if err != nil {
		t.Fatalf("PrepareContext: %v", err)
	}
	opts, ok := tlsutil.ECHDialOptionsFromContext(ctx)
	if !ok {
		t.Fatal("expected ECH options in context")
	}
	if !opts.Enabled || !opts.RequireECH {
		t.Fatalf("unexpected options: %+v", opts)
	}
	if opts.PublicName != "public.example" || opts.InnerSNI != "inner.example" {
		t.Fatalf("unexpected names: %+v", opts)
	}
	if len(opts.ConfigList) == 0 {
		t.Fatal("expected normalized ECH config list")
	}
}

func TestECHOverlayApplyWrapsConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	overlay := &ECHOverlay{
		EnabledField: true,
		PublicName:   "public.example",
		InnerSNI:     "inner.example",
		Configs:      [][]byte{{0x01, 0x02, 0x03}},
		RequireECH:   true,
	}

	wrapped, err := overlay.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	echWrapped, ok := wrapped.(*echConn)
	if !ok {
		t.Fatalf("expected *echConn, got %T", wrapped)
	}
	if echWrapped.publicName != "public.example" || echWrapped.innerSNI != "inner.example" {
		t.Fatalf("unexpected wrapper metadata: %+v", echWrapped)
	}
	if !echWrapped.requireECH {
		t.Fatal("expected requireECH to be true")
	}
	if len(echWrapped.configs) != 1 || len(echWrapped.configs[0]) != 3 {
		t.Fatalf("unexpected config copy: %#v", echWrapped.configs)
	}

	overlay.Configs[0][0] = 0xFF
	if echWrapped.configs[0][0] == 0xFF {
		t.Fatal("ECH configs were not copied defensively")
	}
}
