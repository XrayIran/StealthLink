package covertdtls

import (
	"strings"

	"github.com/theodorsm/covert-dtls/pkg/fingerprints"
)

type CovertDTLSConfig struct {
	Randomize   bool
	Mimic       bool
	Fingerprint fingerprints.ClientHelloFingerprint
}

func ParseConfigString(str string) CovertDTLSConfig {
	config := CovertDTLSConfig{}
	str = strings.ToLower(str)
	switch str {
	case "randomize":
		config.Randomize = true
	case "mimic":
		config.Mimic = true
	case "randomizemimic":
		config.Randomize = true
		config.Mimic = true
	default:
	}

	return config
}
