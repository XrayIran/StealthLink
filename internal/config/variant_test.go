package config

import (
	"encoding/base64"
	"testing"
)

func TestValidateVariantTLSMirrorServerPublicKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Behaviors.Reality.Enabled = true
	cfg.Transport.UQSP.Behaviors.Reality.Dest = "example.com"
	cfg.Transport.UQSP.Behaviors.Reality.PrivateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
	cfg.Transport.UQSP.Behaviors.Reality.ServerPublicKey = base64.StdEncoding.EncodeToString(key)

	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("ValidateVariant returned error for valid server_public_key: %v", err)
	}
}

func TestValidateVariantTLSMirrorServerPublicKeyInvalid(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Behaviors.Reality.Enabled = true
	cfg.Transport.UQSP.Behaviors.Reality.Dest = "example.com"
	cfg.Transport.UQSP.Behaviors.Reality.PrivateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
	cfg.Transport.UQSP.Behaviors.Reality.ServerPublicKey = "not-a-valid-key"

	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected error for invalid server_public_key, got nil")
	}
}
