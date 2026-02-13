package faketcp

import (
	"bytes"
	"testing"

	"pgregory.net/rapid"
)

// Property 15: For any shared secret, the derived client-to-server and server-to-client keys should be different
func TestProperty15_DirectionalKeyUniqueness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.String().Draw(t, "secret")
		keyLen := rapid.SampledFrom([]int{16, 32}).Draw(t, "keyLen")

		kd := NewKeyDerivation(secret)
		keys, err := kd.DeriveDirectionalKeys(keyLen)
		if err != nil {
			t.Fatalf("derive keys failed: %v", err)
		}

		if bytes.Equal(keys.ClientToServer, keys.ServerToClient) {
			t.Fatalf("client-to-server and server-to-client keys are identical")
		}
	})
}

// Property 17: For any AEAD mode (chacha20poly1305 or aesgcm), the derived keys should have the correct length
func TestProperty17_KeyLengthCorrectness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.String().Draw(t, "secret")
		mode := rapid.SampledFrom([]string{"chacha20poly1305", "aesgcm"}).Draw(t, "mode")

		keyLen := 32
		if mode == "aesgcm" {
			keyLen = 16
		}

		kd := NewKeyDerivation(secret)
		keys, err := kd.DeriveDirectionalKeys(keyLen)
		if err != nil {
			t.Fatalf("derive keys failed: %v", err)
		}

		if len(keys.ClientToServer) != keyLen {
			t.Fatalf("c2s key length %d != expected %d", len(keys.ClientToServer), keyLen)
		}
		if len(keys.ServerToClient) != keyLen {
			t.Fatalf("s2c key length %d != expected %d", len(keys.ServerToClient), keyLen)
		}
	})
}

// Property 19: For any plaintext payload and packet metadata, encrypting with AEAD and then decrypting should produce the original plaintext
func TestProperty19_AEADRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mode := rapid.SampledFrom([]string{"chacha20poly1305", "aesgcm"}).Draw(t, "mode")
		keyLen := 32
		if mode == "aesgcm" {
			keyLen = 16
		}
		key := rapid.SliceOfN(rapid.Byte(), keyLen, keyLen).Draw(t, "key")
		plaintext := rapid.SliceOf(rapid.Byte()).Draw(t, "plaintext")

		encryptor, err := NewAEADEncryptor(mode, key)
		if err != nil {
			t.Fatalf("new encryptor: %v", err)
		}

		pkt := &packet{
			Type:   rapid.Uint8().Draw(t, "type"),
			Flags:  rapid.Uint8().Draw(t, "flags"),
			Seq:    rapid.Uint32().Draw(t, "seq"),
			Ack:    rapid.Uint32().Draw(t, "ack"),
			Window: rapid.Uint16().Draw(t, "window"),
		}

		ciphertext := encryptor.Seal(plaintext, pkt)
		decrypted, err := encryptor.Open(ciphertext, pkt)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("decrypted data mismatch")
		}
	})
}

// Property 20: For any ciphertext with an invalid or modified authentication tag, AEAD decryption should fail
func TestProperty20_AEADAuthenticationRejection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mode := rapid.SampledFrom([]string{"chacha20poly1305", "aesgcm"}).Draw(t, "mode")
		keyLen := 32
		if mode == "aesgcm" {
			keyLen = 16
		}
		key := rapid.SliceOfN(rapid.Byte(), keyLen, keyLen).Draw(t, "key")
		plaintext := rapid.SliceOfN(rapid.Byte(), 1, 1024).Draw(t, "plaintext")

		encryptor, err := NewAEADEncryptor(mode, key)
		if err != nil {
			t.Fatalf("new encryptor: %v", err)
		}

		pkt := &packet{Seq: 1}
		ciphertext := encryptor.Seal(plaintext, pkt)

		// Modify one bit of ciphertext
		bitToFlip := rapid.IntRange(0, len(ciphertext)*8-1).Draw(t, "bitToFlip")
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[bitToFlip/8] ^= (1 << (bitToFlip % 8))

		_, err = encryptor.Open(tampered, pkt)
		if err == nil {
			t.Fatalf("decryption should have failed for tampered ciphertext")
		}
	})
}

// Property 21: For any packet with the same fields, the constructed AAD should be identical
func TestProperty21_AADConstructionDeterminism(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pkt := &packet{
			Type:   rapid.Uint8().Draw(t, "type"),
			Flags:  rapid.Uint8().Draw(t, "flags"),
			Seq:    rapid.Uint32().Draw(t, "seq"),
			Ack:    rapid.Uint32().Draw(t, "ack"),
			Window: rapid.Uint16().Draw(t, "window"),
		}

		aad1 := constructAAD(pkt)
		aad2 := constructAAD(pkt)

		if !bytes.Equal(aad1, aad2) {
			t.Fatalf("AAD is not deterministic")
		}
	})
}

// Property 16: For any FakeTCP connection, data encrypted by the client should be decryptable by the server
// using the client-to-server key, and data encrypted by the server should be decryptable by the client
// using the server-to-client key
func TestProperty16_DirectionalEncryptionCorrectness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.String().Draw(t, "secret")
		mode := rapid.SampledFrom([]string{"chacha20poly1305", "aesgcm"}).Draw(t, "mode")
		plaintext := rapid.SliceOf(rapid.Byte()).Draw(t, "plaintext")

		keyLen := 32
		if mode == "aesgcm" {
			keyLen = 16
		}

		// Derive directional keys
		kd := NewKeyDerivation(secret)
		keys, err := kd.DeriveDirectionalKeys(keyLen)
		if err != nil {
			t.Fatalf("derive keys failed: %v", err)
		}

		// Create client and server encryptors
		clientEncryptor, err := NewAEADEncryptor(mode, keys.ClientToServer)
		if err != nil {
			t.Fatalf("create client encryptor: %v", err)
		}

		serverDecryptor, err := NewAEADEncryptor(mode, keys.ClientToServer)
		if err != nil {
			t.Fatalf("create server decryptor: %v", err)
		}

		serverEncryptor, err := NewAEADEncryptor(mode, keys.ServerToClient)
		if err != nil {
			t.Fatalf("create server encryptor: %v", err)
		}

		clientDecryptor, err := NewAEADEncryptor(mode, keys.ServerToClient)
		if err != nil {
			t.Fatalf("create client decryptor: %v", err)
		}

		pkt := &packet{
			Type:   rapid.Uint8().Draw(t, "type"),
			Flags:  rapid.Uint8().Draw(t, "flags"),
			Seq:    rapid.Uint32().Draw(t, "seq"),
			Ack:    rapid.Uint32().Draw(t, "ack"),
			Window: rapid.Uint16().Draw(t, "window"),
		}

		// Test client-to-server direction
		c2sCiphertext := clientEncryptor.Seal(plaintext, pkt)
		c2sDecrypted, err := serverDecryptor.Open(c2sCiphertext, pkt)
		if err != nil {
			t.Fatalf("server decrypt c2s failed: %v", err)
		}
		if !bytes.Equal(plaintext, c2sDecrypted) {
			t.Fatalf("c2s decrypted data mismatch")
		}

		// Test server-to-client direction
		s2cCiphertext := serverEncryptor.Seal(plaintext, pkt)
		s2cDecrypted, err := clientDecryptor.Open(s2cCiphertext, pkt)
		if err != nil {
			t.Fatalf("client decrypt s2c failed: %v", err)
		}
		if !bytes.Equal(plaintext, s2cDecrypted) {
			t.Fatalf("s2c decrypted data mismatch")
		}
	})
}

// Property 18: For any FakeTCP connection, the encryption keys should remain constant for the entire connection lifetime
func TestProperty18_KeyStability(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.String().Draw(t, "secret")
		keyLen := rapid.SampledFrom([]int{16, 32}).Draw(t, "keyLen")

		// Derive keys multiple times with the same secret
		kd1 := NewKeyDerivation(secret)
		keys1, err := kd1.DeriveDirectionalKeys(keyLen)
		if err != nil {
			t.Fatalf("derive keys1 failed: %v", err)
		}

		kd2 := NewKeyDerivation(secret)
		keys2, err := kd2.DeriveDirectionalKeys(keyLen)
		if err != nil {
			t.Fatalf("derive keys2 failed: %v", err)
		}

		// Keys should be identical for the same secret
		if !bytes.Equal(keys1.ClientToServer, keys2.ClientToServer) {
			t.Fatalf("c2s keys differ for same secret")
		}
		if !bytes.Equal(keys1.ServerToClient, keys2.ServerToClient) {
			t.Fatalf("s2c keys differ for same secret")
		}
	})
}

// Property 22: For any two different packets in a connection, their constructed nonces should be different
func TestProperty22_NonceUniqueness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pkt1 := &packet{
			Type:  rapid.Uint8().Draw(t, "type1"),
			Flags: rapid.Uint8().Draw(t, "flags1"),
			Seq:   rapid.Uint32().Draw(t, "seq1"),
			Ack:   rapid.Uint32().Draw(t, "ack1"),
		}
		pkt2 := &packet{
			Type:  rapid.Uint8().Draw(t, "type2"),
			Flags: rapid.Uint8().Draw(t, "flags2"),
			Seq:   rapid.Uint32().Draw(t, "seq2"),
			Ack:   rapid.Uint32().Draw(t, "ack2"),
		}

		// Ensure packets are different in some way that affects nonce
		if pkt1.Type == pkt2.Type && pkt1.Flags == pkt2.Flags && pkt1.Seq == pkt2.Seq && pkt1.Ack == pkt2.Ack {
			return
		}

		nonce1 := constructNonce(pkt1)
		nonce2 := constructNonce(pkt2)

		if bytes.Equal(nonce1, nonce2) {
			t.Fatalf("different packets produced same nonce")
		}
	})
}

// Property 23: For any configured MTU value M, when AEAD mode is enabled, the effective MTU should be (M - 16 - header_size)
func TestProperty23_MTUAdjustment(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		baseMTU := rapid.IntRange(500, 9000).Draw(t, "mtu")
		aeadMode := rapid.SampledFrom([]string{"off", "chacha20poly1305", "aesgcm"}).Draw(t, "aeadMode")

		cfg := &Config{
			MTU:       baseMTU,
			CryptoKey: "test-secret",
			AEADMode:  aeadMode,
		}

		// Create a fake session to test MTU calculation
		cryptoCtx, err := buildSessionCrypto(cfg, true)
		if err != nil {
			t.Fatalf("build session crypto: %v", err)
		}

		session := &fakeSession{
			config: cfg,
			crypto: cryptoCtx,
		}

		effectiveMTU := session.effectiveMTU()

		// Expected MTU calculation
		expectedMTU := baseMTU - HeaderSize
		if aeadMode != "off" && aeadMode != "" {
			expectedMTU -= 16 // AEAD tag size
		}

		if effectiveMTU != expectedMTU {
			t.Fatalf("effective MTU %d != expected %d (base=%d, aead=%s)", effectiveMTU, expectedMTU, baseMTU, aeadMode)
		}
	})
}
