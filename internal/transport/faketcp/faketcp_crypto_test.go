package faketcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectionalKeyDerivation(t *testing.T) {
	secret := "test-shared-secret"
	kd := NewKeyDerivation(secret)

	keys1, err := kd.DeriveDirectionalKeys(32)
	require.NoError(t, err)
	assert.NotEqual(t, keys1.ClientToServer, keys1.ServerToClient)

	keys2, err := kd.DeriveDirectionalKeys(32)
	require.NoError(t, err)
	assert.Equal(t, keys1.ClientToServer, keys2.ClientToServer)
	assert.Equal(t, keys1.ServerToClient, keys2.ServerToClient)
}

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	encryptor, err := NewAEADEncryptor("chacha20poly1305", key)
	require.NoError(t, err)

	pkt := &packet{
		Type:   PacketTypeData,
		Flags:  0x01,
		Seq:    1234,
		Ack:    5678,
		Window: 1024,
	}

	plaintext := []byte("hello world")
	ciphertext := encryptor.Seal(plaintext, pkt)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := encryptor.Open(ciphertext, pkt)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAEADAuthFailure(t *testing.T) {
	key := make([]byte, 32)
	encryptor, err := NewAEADEncryptor("chacha20poly1305", key)
	require.NoError(t, err)

	pkt := &packet{Seq: 1}
	plaintext := []byte("secret")
	ciphertext := encryptor.Seal(plaintext, pkt)

	// Tamper ciphertext
	ciphertext[0] ^= 0xFF

	_, err = encryptor.Open(ciphertext, pkt)
	assert.Error(t, err)

	// Tamper AAD (by changing pkt)
	pkt.Seq = 2
	_, err = encryptor.Open(ciphertext, pkt)
	assert.Error(t, err)
}

func TestAADConstruction(t *testing.T) {
	pkt := &packet{
		Type:   PacketTypeData,
		Flags:  0x01,
		Seq:    0x11223344,
		Ack:    0x55667788,
		Window: 0xAABB,
	}

	aad := constructAAD(pkt)
	expected := []byte{
		0x04, 0x01, // Type, Flags
		0x11, 0x22, 0x33, 0x44, // Seq
		0x55, 0x66, 0x77, 0x88, // Ack
		0xAA, 0xBB, // Window
	}
	assert.Equal(t, expected, aad)
}

func TestNonceConstruction(t *testing.T) {
	pkt := &packet{
		Type:  PacketTypeData,
		Flags: 0x01,
		Seq:   0x11223344,
		Ack:   0x55667788,
	}

	nonce := constructNonce(pkt)
	expected := []byte{
		0x11, 0x22, 0x33, 0x44, // Seq
		0x55, 0x66, 0x77, 0x88, // Ack
		0x04, 0x01, // Type, Flags
		0x00, 0x00, // Zeros
	}
	assert.Equal(t, expected, nonce)
}

func TestNonceUniqueness(t *testing.T) {
	// Test that different packets produce different nonces
	pkt1 := &packet{
		Type:   PacketTypeData,
		Flags:  0x01,
		Seq:    1000,
		Ack:    2000,
		Window: 1024,
	}

	pkt2 := &packet{
		Type:   PacketTypeData,
		Flags:  0x01,
		Seq:    1001, // Different sequence
		Ack:    2000,
		Window: 1024,
	}

	pkt3 := &packet{
		Type:   PacketTypeData,
		Flags:  0x01,
		Seq:    1000,
		Ack:    2001, // Different ack
		Window: 1024,
	}

	pkt4 := &packet{
		Type:   PacketTypeSYN, // Different type
		Flags:  0x01,
		Seq:    1000,
		Ack:    2000,
		Window: 1024,
	}

	pkt5 := &packet{
		Type:   PacketTypeData,
		Flags:  0x02, // Different flags
		Seq:    1000,
		Ack:    2000,
		Window: 1024,
	}

	nonce1 := constructNonce(pkt1)
	nonce2 := constructNonce(pkt2)
	nonce3 := constructNonce(pkt3)
	nonce4 := constructNonce(pkt4)
	nonce5 := constructNonce(pkt5)

	// All nonces should be different
	assert.NotEqual(t, nonce1, nonce2, "Different seq should produce different nonces")
	assert.NotEqual(t, nonce1, nonce3, "Different ack should produce different nonces")
	assert.NotEqual(t, nonce1, nonce4, "Different type should produce different nonces")
	assert.NotEqual(t, nonce1, nonce5, "Different flags should produce different nonces")

	// Verify nonce length is always 12 bytes
	assert.Len(t, nonce1, 12)
	assert.Len(t, nonce2, 12)
	assert.Len(t, nonce3, 12)
	assert.Len(t, nonce4, 12)
	assert.Len(t, nonce5, 12)
}

func TestMTUAdjustment(t *testing.T) {
	tests := []struct {
		name        string
		mtu         int
		aeadEnabled bool
		expected    int
	}{
		{
			name:        "Default MTU without AEAD",
			mtu:         1400,
			aeadEnabled: false,
			expected:    1400 - 24, // 1376 (subtract FakeTCP header)
		},
		{
			name:        "Default MTU with AEAD",
			mtu:         1400,
			aeadEnabled: true,
			expected:    1400 - 24 - 16, // 1360 (subtract header + AEAD tag)
		},
		{
			name:        "Custom MTU without AEAD",
			mtu:         1500,
			aeadEnabled: false,
			expected:    1500 - 24, // 1476
		},
		{
			name:        "Custom MTU with AEAD",
			mtu:         1500,
			aeadEnabled: true,
			expected:    1500 - 24 - 16, // 1460
		},
		{
			name:        "Zero MTU defaults to 1400 without AEAD",
			mtu:         0,
			aeadEnabled: false,
			expected:    1400 - 24, // 1376
		},
		{
			name:        "Zero MTU defaults to 1400 with AEAD",
			mtu:         0,
			aeadEnabled: true,
			expected:    1400 - 24 - 16, // 1360
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &fakeSession{
				config: &Config{
					MTU: tt.mtu,
				},
			}

			if tt.aeadEnabled {
				// Create a minimal crypto setup
				session.crypto = &sessionCrypto{
					enabled: true,
				}
			}

			effectiveMTU := session.effectiveMTU()
			assert.Equal(t, tt.expected, effectiveMTU, "MTU adjustment incorrect")
		})
	}
}
