package warp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RegistrationClient handles WARP device registration with Cloudflare.
type RegistrationClient struct {
	httpClient *http.Client
	baseURL    string
	plusURL    string
}

// NewRegistrationClient creates a new registration client.
func NewRegistrationClient() *RegistrationClient {
	return &RegistrationClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.cloudflareclient.com/v0a2158",
		plusURL: "https://api.cloudflareclient.com/v0a2158/reg",
	}
}

// RegisterDevice registers a new WARP device with Cloudflare.
func (c *RegistrationClient) RegisterDevice(publicKey string) (*WARPDevice, error) {
	reg := DefaultRegistration(publicKey)

	body, err := json.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("marshal registration: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/reg", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", "a-7.21-0721")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var acctResp AccountResponse
	if err := json.Unmarshal(respBody, &acctResp); err != nil {
		return nil, fmt.Errorf("parse registration response: %w", err)
	}

	device := &WARPDevice{
		ID:        acctResp.ID,
		Name:      "StealthLink WARP",
		PublicKey: publicKey,
		Token:     acctResp.Token,
	}

	// Extract IP addresses from config if available
	if acctResp.Config.Interface.Addresses.V4 != "" {
		device.IPv4 = acctResp.Config.Interface.Addresses.V4
	}
	if acctResp.Config.Interface.Addresses.V6 != "" {
		device.IPv6 = acctResp.Config.Interface.Addresses.V6
	}

	return device, nil
}

// GetConfig retrieves the WARP configuration for a device.
func (c *RegistrationClient) GetConfig(deviceID, accessToken string) (*WARPConfigResponse, error) {
	url := fmt.Sprintf("%s/reg/%s", c.baseURL, deviceID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("CF-Client-Version", "a-7.21-0721")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get config failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var acctResp AccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&acctResp); err != nil {
		return nil, fmt.Errorf("parse config response: %w", err)
	}

	return &acctResp.Config, nil
}

// RegisterWARPPlusLicense binds a WARP+ license to a registered device.
func (c *RegistrationClient) RegisterWARPPlusLicense(deviceID, accessToken, license string) error {
	if deviceID == "" || accessToken == "" || license == "" {
		return fmt.Errorf("device id, access token, and license are required")
	}

	body, err := json.Marshal(map[string]string{
		"license": license,
	})
	if err != nil {
		return fmt.Errorf("marshal license request: %w", err)
	}

	url := fmt.Sprintf("%s/%s/account", c.plusURL, deviceID)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("CF-Client-Version", "a-7.21-0721")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("register WARP+ license: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register WARP+ failed: HTTP %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

// RegisterDeviceWithPlus registers a new device and optionally upgrades it with a WARP+ license.
func (c *RegistrationClient) RegisterDeviceWithPlus(publicKey, license string) (*WARPDevice, error) {
	dev, err := c.RegisterDevice(publicKey)
	if err != nil {
		return nil, err
	}
	if license == "" {
		return dev, nil
	}
	if err := c.RegisterWARPPlusLicense(dev.ID, dev.Token, license); err != nil {
		return nil, err
	}
	return dev, nil
}

// WARPConfigResponse contains the WARP configuration from Cloudflare.
type WARPConfigResponse struct {
	Interface WARPInterfaceConfig `json:"interface"`
	Peers     []WARPPeerConfig    `json:"peers"`
}

// WARPInterfaceConfig contains interface configuration.
type WARPInterfaceConfig struct {
	Addresses WARPAddresses `json:"addresses"`
	DNS       WARPDNS       `json:"dns"`
}

// WARPAddresses contains the IP addresses.
type WARPAddresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

// WARPDNS contains DNS configuration.
type WARPDNS struct {
	Servers []string `json:"servers"`
}

// WARPPeerConfig contains peer (server) configuration.
type WARPPeerConfig struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
}

// AccountRegistration registers a WARP account.
type AccountRegistration struct {
	Type      string `json:"type"`
	Model     string `json:"model"`
	Locale    string `json:"locale"`
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FCMToken  string `json:"fcm_token,omitempty"`
}

// AccountResponse is the response from registration.
type AccountResponse struct {
	ID      string             `json:"id"`
	Type    string             `json:"type"`
	Model   string             `json:"model"`
	Token   string             `json:"token"`
	Account WARPAccount        `json:"account"`
	Config  WARPConfigResponse `json:"config"`
}

// WARPAccount contains account information.
type WARPAccount struct {
	ID          string    `json:"id"`
	Type        string    `json:"account_type"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	PremiumData int64     `json:"premium_data"`
	Quota       int64     `json:"quota"`
	Usage       int64     `json:"usage"`
	WarpPlus    bool      `json:"warp_plus"`
}

// GenerateInstallID generates a cryptographically random install ID.
func GenerateInstallID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// DefaultRegistration returns a default registration.
func DefaultRegistration(publicKey string) *AccountRegistration {
	return &AccountRegistration{
		Type:      "Linux",
		Model:     "StealthLink",
		Locale:    "en_US",
		Key:       publicKey,
		InstallID: GenerateInstallID(),
	}
}
