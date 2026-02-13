package xhttpmeta

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Placement controls where metadata is encoded in an XHTTP request.
type Placement string

const (
	PlacementHeader Placement = "header"
	PlacementPath   Placement = "path"
	PlacementQuery  Placement = "query"
	PlacementCookie Placement = "cookie"
)

// FieldConfig describes placement and key name for a metadata field.
type FieldConfig struct {
	Placement Placement `yaml:"placement"`
	Key       string    `yaml:"key"`
}

// MetadataConfig controls session/sequence/mode metadata encoding.
type MetadataConfig struct {
	Session FieldConfig `yaml:"session"`
	Seq     FieldConfig `yaml:"seq"`
	Mode    FieldConfig `yaml:"mode"`
}

// MetadataValues are per-request metadata values.
type MetadataValues struct {
	SessionID string
	Seq       uint64
	Mode      string
}

// ApplyDefaults fills unset placements/keys with compatible defaults.
func (c *MetadataConfig) ApplyDefaults() {
	if c.Session.Placement == "" {
		c.Session.Placement = PlacementHeader
	}
	if c.Seq.Placement == "" {
		c.Seq.Placement = PlacementHeader
	}
	if c.Mode.Placement == "" {
		c.Mode.Placement = PlacementHeader
	}

	if c.Session.Key == "" {
		c.Session.Key = "X-Session-ID"
	}
	if c.Seq.Key == "" {
		c.Seq.Key = "X-Seq"
	}
	if c.Mode.Key == "" {
		c.Mode.Key = "X-Stealthlink-Mode"
	}
}

// KeyValidator handles key name validation and collision detection.
type KeyValidator struct{}

func (v *KeyValidator) ValidateKey(key string, p Placement) error {
	if key == "" {
		return fmt.Errorf("key name cannot be empty")
	}
	switch p {
	case PlacementHeader:
		// RFC 7230 token characters: tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*"
		// / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
		for _, r := range key {
			if !isToken(r) {
				return fmt.Errorf("invalid key name for placement: %s", key)
			}
		}
	case PlacementCookie:
		// RFC 6265 cookie-name: token
		for _, r := range key {
			if !isToken(r) {
				return fmt.Errorf("invalid key name for placement: %s", key)
			}
		}
	}
	return nil
}

func isToken(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", r)
}

func (c *MetadataConfig) Validate() error {
	v := &KeyValidator{}
	configs := []FieldConfig{c.Session, c.Seq, c.Mode}
	keys := make(map[string]bool)

	for _, f := range configs {
		if err := v.ValidateKey(f.Key, f.Placement); err != nil {
			return err
		}
		// Collision detection among metadata keys
		if keys[f.Key] {
			return fmt.Errorf("key name collision detected: %s", f.Key)
		}
		keys[f.Key] = true

		// Check for specific placement types
		switch f.Placement {
		case PlacementHeader, PlacementPath, PlacementQuery, PlacementCookie:
			// OK
		default:
			return fmt.Errorf("unsupported metadata placement: %s", f.Placement)
		}
	}
	return nil
}

// PlacementEncoder encodes metadata into HTTP requests.
type PlacementEncoder struct {
	Config MetadataConfig
}

func NewPlacementEncoder(cfg MetadataConfig) *PlacementEncoder {
	cfg.ApplyDefaults()
	return &PlacementEncoder{Config: cfg}
}

func (e *PlacementEncoder) Encode(req *http.Request, values MetadataValues) error {
	if len(values.SessionID) > 128 {
		return fmt.Errorf("session ID too long")
	}

	// Session ID encoding: base64url no padding
	sessionVal := base64.RawURLEncoding.EncodeToString([]byte(values.SessionID))

	// Sequence encoding: decimal integer
	seqVal := strconv.FormatUint(values.Seq, 10)

	if err := e.applyField(req, e.Config.Session, sessionVal); err != nil {
		return err
	}
	if err := e.applyField(req, e.Config.Seq, seqVal); err != nil {
		return err
	}
	if err := e.applyField(req, e.Config.Mode, values.Mode); err != nil {
		return err
	}

	return nil
}

func (e *PlacementEncoder) applyField(req *http.Request, f FieldConfig, val string) error {
	if val == "" {
		return nil
	}

	switch f.Placement {
	case PlacementHeader:
		req.Header.Set(f.Key, val)
	case PlacementQuery:
		q := req.URL.Query()
		if q.Get(f.Key) != "" {
			return fmt.Errorf("key name collision detected: %s", f.Key)
		}
		q.Set(f.Key, val)
		req.URL.RawQuery = q.Encode()
	case PlacementCookie:
		for _, c := range req.Cookies() {
			if c.Name == f.Key {
				return fmt.Errorf("key name collision detected: %s", f.Key)
			}
		}
		req.AddCookie(&http.Cookie{Name: f.Key, Value: val})
	case PlacementPath:
		p := strings.TrimSuffix(req.URL.Path, "/")
		if p == "" {
			req.URL.Path = "/" + url.PathEscape(f.Key) + "/" + url.PathEscape(val)
		} else {
			req.URL.Path = p + "/" + url.PathEscape(f.Key) + "/" + url.PathEscape(val)
		}
	}
	return nil
}

// PlacementDecoder extracts metadata from HTTP requests.
type PlacementDecoder struct {
	Config MetadataConfig
}

func NewPlacementDecoder(cfg MetadataConfig) *PlacementDecoder {
	cfg.ApplyDefaults()
	return &PlacementDecoder{Config: cfg}
}

func (d *PlacementDecoder) Decode(req *http.Request) (MetadataValues, error) {
	var values MetadataValues

	sessionRaw, err := d.extractField(req, d.Config.Session)
	if err != nil {
		return values, err
	}
	if sessionRaw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(sessionRaw)
		if err != nil {
			return values, fmt.Errorf("invalid session ID encoding: %v", err)
		}
		values.SessionID = string(decoded)
	}

	seqRaw, err := d.extractField(req, d.Config.Seq)
	if err != nil {
		return values, err
	}
	if seqRaw != "" {
		val, err := strconv.ParseUint(seqRaw, 10, 64)
		if err != nil {
			return values, fmt.Errorf("invalid sequence number: %v", err)
		}
		values.Seq = val
	}

	modeRaw, err := d.extractField(req, d.Config.Mode)
	if err != nil {
		return values, err
	}
	values.Mode = modeRaw

	return values, nil
}

func (d *PlacementDecoder) extractField(req *http.Request, f FieldConfig) (string, error) {
	switch f.Placement {
	case PlacementHeader:
		return req.Header.Get(f.Key), nil
	case PlacementQuery:
		return req.URL.Query().Get(f.Key), nil
	case PlacementCookie:
		c, err := req.Cookie(f.Key)
		if err == http.ErrNoCookie {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return c.Value, nil
	case PlacementPath:
		pairs := decodePathPairs(req.URL.Path)
		if v, ok := pairs[f.Key]; ok {
			return v, nil
		}
		return "", nil
	}
	return "", nil
}

// decodePathPairs decodes key/value metadata appended to the request path.
// Path metadata is always encoded as ".../<key>/<value>" segments, appended
// at the end. We parse from the tail to avoid collisions where a metadata
// value equals another metadata key.
func decodePathPairs(path string) map[string]string {
	result := make(map[string]string)
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return result
	}

	parts := strings.Split(trimmed, "/")
	for i := len(parts) - 2; i >= 0; i -= 2 {
		key, err := url.PathUnescape(parts[i])
		if err != nil || key == "" {
			continue
		}
		val, err := url.PathUnescape(parts[i+1])
		if err != nil {
			continue
		}
		if _, exists := result[key]; !exists {
			result[key] = val
		}
	}

	return result
}

// BuildURL is a helper for client-side URL construction with metadata.
func BuildURL(rawURL string, cfg MetadataConfig, values MetadataValues) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	req, _ := http.NewRequest(http.MethodPost, u.String(), nil)
	enc := NewPlacementEncoder(cfg)
	if err := enc.Encode(req, values); err != nil {
		return "", err
	}
	return req.URL.String(), nil
}

// ApplyToRequest is a helper for applying metadata to a request.
func ApplyToRequest(req *http.Request, cfg MetadataConfig, values MetadataValues) error {
	enc := NewPlacementEncoder(cfg)
	return enc.Encode(req, values)
}
