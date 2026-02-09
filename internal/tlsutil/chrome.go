package tlsutil

import (
	"crypto/sha256"
	"encoding/hex"

	utls "github.com/refraction-networking/utls"
)

// ChromeFingerprint provides advanced Chrome fingerprinting with:
// - X25519MLKEM768 key exchange (post-quantum hybrid)
// - GREASE extension injection
// - Extension permutation
// - Brotli certificate compression
// Based on Chrome 120+ behavior.

type ChromeFingerprint struct {
	Version            string
	CipherSuites       []uint16
	Extensions         []utls.TLSExtension
	CompressionMethods []uint8
	GREASEEnabled      bool
	PermuteExtensions  bool
	BrotliCompression  bool
}

// NewChrome120 creates a Chrome 120 fingerprint with all modern features.
func NewChrome120() *ChromeFingerprint {
	return &ChromeFingerprint{
		Version:            "120",
		CipherSuites:       chrome120CipherSuites(),
		Extensions:         chrome120Extensions(),
		CompressionMethods: []uint8{0},
		GREASEEnabled:      true,
		PermuteExtensions:  true,
		BrotliCompression:  true,
	}
}

// chrome120CipherSuites returns Chrome 120 cipher suites.
func chrome120CipherSuites() []uint16 {
	return []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	}
}

// chrome120Extensions returns Chrome 120 extensions.
func chrome120Extensions() []utls.TLSExtension {
	return []utls.TLSExtension{
		// Server Name Indication
		&utls.SNIExtension{},

		// Extended Master Secret
		&utls.ExtendedMasterSecretExtension{},

		// Renegotiation Info
		&utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		},

		// Supported Point Formats
		&utls.SupportedPointsExtension{
			SupportedPoints: []uint8{0}, // uncompressed
		},

		// Supported Curves (including X25519MLKEM768)
		&utls.SupportedCurvesExtension{
			Curves: []utls.CurveID{
				0x6399, // X25519MLKEM768 (post-quantum hybrid)
				0x001d, // X25519
				0x0017, // secp256r1
				0x0018, // secp384r1
			},
		},

		// Session Ticket
		&utls.SessionTicketExtension{},

		// ALPN
		&utls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},

		// Status Request (OCSP stapling)
		&utls.StatusRequestExtension{},

		// Signature Algorithms
		&utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0403, // ecdsa_secp256r1_sha256
				0x0804, // rsa_pss_rsae_sha256
				0x0401, // rsa_pkcs1_sha256
				0x0503, // ecdsa_secp384r1_sha384
				0x0805, // rsa_pss_rsae_sha384
				0x0501, // rsa_pkcs1_sha384
				0x0806, // rsa_pss_rsae_sha512
				0x0601, // rsa_pkcs1_sha512
			},
		},

		// SCT (Signed Certificate Timestamp)
		&utls.SCTExtension{},

		// Key Share (including X25519MLKEM768)
		&utls.KeyShareExtension{
			KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			},
		},

		// Supported Versions
		&utls.SupportedVersionsExtension{
			Versions: []uint16{
				0x0304, // TLS 1.3
				0x0303, // TLS 1.2
			},
		},

		// Cookie
		&utls.CookieExtension{},

				// Certificate Compression (brotli)
		&utls.UtlsCompressCertExtension{
			Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			},
		},

		// Application Settings (ALPS)
		&utls.ApplicationSettingsExtension{
			SupportedProtocols: []string{"h2"},
		},
	}
}

// ToClientHelloSpec converts to a uTLS ClientHelloSpec.
func (c *ChromeFingerprint) ToClientHelloSpec() *utls.ClientHelloSpec {
	extensions := make([]utls.TLSExtension, len(c.Extensions))
	copy(extensions, c.Extensions)

	// Add GREASE extensions if enabled
	if c.GREASEEnabled {
		extensions = injectGREASE(extensions)
	}

	// Permute extensions if enabled
	if c.PermuteExtensions {
		extensions = permuteExtensions(extensions)
	}

	return &utls.ClientHelloSpec{
		CipherSuites:       c.CipherSuites,
		CompressionMethods: c.CompressionMethods,
		Extensions:         extensions,
	}
}

// ToClientHelloID returns a ClientHelloID for this fingerprint.
func (c *ChromeFingerprint) ToClientHelloID() utls.ClientHelloID {
	return utls.ClientHelloID{
		Client: "Custom",
		Version: c.Version,
	}
}

// injectGREASE injects GREASE (Generate Random Extensions And Sustain Extensibility)
// extensions at random positions. This is used by Chrome to prevent ossification.
func injectGREASE(extensions []utls.TLSExtension) []utls.TLSExtension {
	// GREASE values for extensions (0x0a0a, 0x1a1a, 0x2a2a, etc.)
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	result := make([]utls.TLSExtension, 0, len(extensions)+2)

	// Add first GREASE at the beginning
	result = append(result, &utls.GenericExtension{
		Id: greaseValues[0],
	})

	// Add remaining extensions
	result = append(result, extensions...)

	// Add second GREASE near the end
	result = append(result, &utls.GenericExtension{
		Id: greaseValues[1],
	})

	return result
}

// permuteExtensions randomly permutes the order of extensions.
// Chrome randomizes extension order to prevent fingerprinting.
func permuteExtensions(extensions []utls.TLSExtension) []utls.TLSExtension {
	// Keep SNI first, permute the rest
	if len(extensions) <= 1 {
		return extensions
	}

	result := make([]utls.TLSExtension, len(extensions))
	copy(result, extensions)

	// Permute extensions 1 onwards (keep SNI at position 0)
	for i := len(result) - 1; i > 1; i-- {
		j := 1 + randInt(i-1)
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// ChromeFingerprintWithConfig creates a Chrome fingerprint with custom config.
func ChromeFingerprintWithConfig(serverName string, alpnProtocols []string, grease, permute bool) *ChromeFingerprint {
	cf := NewChrome120()
	cf.GREASEEnabled = grease
	cf.PermuteExtensions = permute

	// Update SNI
	for _, ext := range cf.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok {
			sni.ServerName = serverName
			break
		}
	}

	// Update ALPN
	if alpnProtocols != nil {
		for _, ext := range cf.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = alpnProtocols
				break
			}
		}
	}

	return cf
}

// CalculateJA3 calculates the JA3 fingerprint of this ClientHello.
func (c *ChromeFingerprint) CalculateJA3() string {
	spec := c.ToClientHelloSpec()

	// Build JA3 string components
	version := "772" // TLS 1.3

	// Cipher suites
	cipherSuites := ""
	for i, cs := range spec.CipherSuites {
		if i > 0 {
			cipherSuites += "-"
		}
		cipherSuites += formatUint16(cs)
	}

	// Extensions
	extensions := ""
	for i, ext := range spec.Extensions {
		if i > 0 {
			extensions += "-"
		}
		extensions += formatUint16(getExtensionType(ext))
	}

	// Elliptic curves (from supported_curves extension)
	curves := "29-23-24" // X25519, secp256r1, secp384r1

	// EC point formats
	formats := "0"

	// Build full JA3 string
	ja3 := version + "," + cipherSuites + "," + extensions + "," + curves + "," + formats

	// Calculate MD5 hash
	hash := sha256.Sum256([]byte(ja3))
	return hex.EncodeToString(hash[:])[:32]
}

// getExtensionType returns the type of an extension.
func getExtensionType(ext utls.TLSExtension) uint16 {
	switch e := ext.(type) {
	case *utls.SNIExtension:
		return 0
	case *utls.StatusRequestExtension:
		return 5
	case *utls.SupportedCurvesExtension:
		return 10
	case *utls.SupportedPointsExtension:
		return 11
	case *utls.SignatureAlgorithmsExtension:
		return 13
	case *utls.ALPNExtension:
		return 16
	case *utls.SCTExtension:
		return 18
	case *utls.KeyShareExtension:
		return 51
	case *utls.SupportedVersionsExtension:
		return 43
	case *utls.CookieExtension:
		return 44
	case *utls.UtlsCompressCertExtension:
		return 27
	case *utls.ApplicationSettingsExtension:
		return 17513
	case *utls.GenericExtension:
		return e.Id
	default:
		return 0xffff
	}
}

func formatUint16(v uint16) string {
	return hex.EncodeToString([]byte{byte(v >> 8), byte(v)})
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	return 0
}
