package uqsp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/transport/obfs"
)

// ObfuscationType represents the type of obfuscation
type ObfuscationType int

const (
	ObfuscationTypeNone ObfuscationType = iota
	ObfuscationTypeSalamander
	ObfuscationTypeAdaptive
)

// Obfuscator handles UQSP obfuscation
type Obfuscator struct {
	// obfuscationType is the type of obfuscation
	obfuscationType ObfuscationType

	// salamander is the salamander obfuscator (if used)
	salamander *obfs.SalamanderObfuscator

	// config holds obfuscation configuration
	config *ObfuscationConfig

	// paddingMin is the minimum padding size
	paddingMin int

	// paddingMax is the maximum padding size
	paddingMax int

	// timingJitterMs is the timing jitter in milliseconds
	timingJitterMs int

	// mu protects the obfuscator state
	mu sync.RWMutex
}

// ObfuscationConfig configures obfuscation
type ObfuscationConfig struct {
	// Type is the obfuscation type
	Type string

	// SalamanderKey is the key for salamander obfuscation
	SalamanderKey string

	// PaddingMin is the minimum padding size
	PaddingMin int

	// PaddingMax is the maximum padding size
	PaddingMax int

	// TimingJitterMs is the timing jitter in milliseconds
	TimingJitterMs int

	// MorphingEnabled enables header morphing
	MorphingEnabled bool
}

// NewObfuscator creates a new obfuscator
func NewObfuscator(config *ObfuscationConfig) (*Obfuscator, error) {
	if config == nil {
		config = &ObfuscationConfig{
			Type:       "none",
			PaddingMin: 16,
			PaddingMax: 128,
		}
	}

	o := &Obfuscator{
		config:     config,
		paddingMin: config.PaddingMin,
		paddingMax: config.PaddingMax,
	}

	// Determine obfuscation type
	switch config.Type {
	case "salamander":
		o.obfuscationType = ObfuscationTypeSalamander
		if config.SalamanderKey == "" {
			return nil, fmt.Errorf("salamander key is required")
		}
		salamander, err := obfs.NewSalamander(config.SalamanderKey)
		if err != nil {
			return nil, fmt.Errorf("create salamander: %w", err)
		}
		o.salamander = salamander
	case "adaptive":
		o.obfuscationType = ObfuscationTypeAdaptive
		// Adaptive mode may use salamander if key is provided
		if config.SalamanderKey != "" {
			salamander, err := obfs.NewSalamander(config.SalamanderKey)
			if err != nil {
				return nil, fmt.Errorf("create salamander: %w", err)
			}
			o.salamander = salamander
		}
	default:
		o.obfuscationType = ObfuscationTypeNone
	}

	return o, nil
}

// ObfuscatePacket obfuscates a packet
func (o *Obfuscator) ObfuscatePacket(data []byte) ([]byte, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	switch o.obfuscationType {
	case ObfuscationTypeSalamander:
		if o.salamander == nil {
			return nil, fmt.Errorf("salamander not initialized")
		}
		return o.salamander.Obfuscate(data)
	case ObfuscationTypeAdaptive:
		// In adaptive mode, we may or may not obfuscate based on conditions
		if o.salamander != nil && o.shouldObfuscate() {
			return o.salamander.Obfuscate(data)
		}
		return data, nil
	default:
		return data, nil
	}
}

// DeobfuscatePacket deobfuscates a packet
func (o *Obfuscator) DeobfuscatePacket(data []byte) ([]byte, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	switch o.obfuscationType {
	case ObfuscationTypeSalamander:
		if o.salamander == nil {
			return nil, fmt.Errorf("salamander not initialized")
		}
		return o.salamander.Deobfuscate(data)
	case ObfuscationTypeAdaptive:
		// Try to deobfuscate, if it fails return original data
		if o.salamander != nil {
			result, err := o.salamander.Deobfuscate(data)
			if err == nil {
				return result, nil
			}
		}
		return data, nil
	default:
		return data, nil
	}
}

// shouldObfuscate returns true if we should obfuscate in adaptive mode
func (o *Obfuscator) shouldObfuscate() bool {
	// Simple adaptive logic: obfuscate 50% of packets
	// This can be made more sophisticated based on network conditions
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false
	}
	return b[0]&1 == 0
}

// GetPadding returns random padding bytes
func (o *Obfuscator) GetPadding() []byte {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.paddingMax <= o.paddingMin {
		return nil
	}

	// Random padding size between min and max
	size := o.paddingMin
	if o.paddingMax > o.paddingMin {
		range_ := o.paddingMax - o.paddingMin
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil
		}
		size += int(binary.BigEndian.Uint32(b[:])) % range_
	}

	padding := make([]byte, size)
	if _, err := rand.Read(padding); err != nil {
		return nil
	}
	return padding
}

// GetTimingJitter returns a random timing jitter duration
func (o *Obfuscator) GetTimingJitter() time.Duration {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.timingJitterMs <= 0 {
		return 0
	}

	// Random jitter between 0 and timingJitterMs
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	jitter := int(binary.BigEndian.Uint32(b[:])) % o.timingJitterMs
	return time.Duration(jitter) * time.Millisecond
}

// UpdateConfig updates the obfuscation configuration
func (o *Obfuscator) UpdateConfig(config *ObfuscationConfig) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.paddingMin = config.PaddingMin
	o.paddingMax = config.PaddingMax
	o.timingJitterMs = config.TimingJitterMs

	// Update obfuscation type if changed
	if config.Type != o.config.Type {
		o.config.Type = config.Type
		switch config.Type {
		case "salamander":
			o.obfuscationType = ObfuscationTypeSalamander
			if config.SalamanderKey != "" && o.salamander == nil {
				salamander, err := obfs.NewSalamander(config.SalamanderKey)
				if err != nil {
					return fmt.Errorf("create salamander: %w", err)
				}
				o.salamander = salamander
			}
		case "adaptive":
			o.obfuscationType = ObfuscationTypeAdaptive
		default:
			o.obfuscationType = ObfuscationTypeNone
		}
	}

	return nil
}

// ObfuscatedConn wraps a net.Conn with obfuscation
type ObfuscatedConn struct {
	net.Conn
	obfuscator *Obfuscator
	readBuf    []byte
	writeBuf   []byte
	mu         sync.Mutex
}

// NewObfuscatedConn creates a new obfuscated connection
func NewObfuscatedConn(conn net.Conn, obfuscator *Obfuscator) *ObfuscatedConn {
	return &ObfuscatedConn{
		Conn:       conn,
		obfuscator: obfuscator,
		readBuf:    make([]byte, 0, 65536),
		writeBuf:   make([]byte, 0, 65536),
	}
}

// Read reads and deobfuscates data
func (c *ObfuscatedConn) Read(b []byte) (int, error) {
	// If we have buffered data, return it
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read obfuscated packet length
	var lenBuf [2]byte
	if _, err := c.Conn.Read(lenBuf[:]); err != nil {
		return 0, err
	}
	pktLen := binary.BigEndian.Uint16(lenBuf[:])

	if pktLen == 0 || pktLen > 16384 {
		return 0, fmt.Errorf("invalid packet length: %d", pktLen)
	}

	// Read obfuscated packet
	obfData := make([]byte, pktLen)
	if _, err := c.Conn.Read(obfData); err != nil {
		return 0, err
	}

	// Deobfuscate
	data, err := c.obfuscator.DeobfuscatePacket(obfData)
	if err != nil {
		return 0, err
	}

	// Copy to buffer
	n := copy(b, data)
	if n < len(data) {
		// Store remainder
		c.readBuf = append(c.readBuf, data[n:]...)
	}

	return n, nil
}

// Write writes and obfuscates data
func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Obfuscate data
	obfData, err := c.obfuscator.ObfuscatePacket(b)
	if err != nil {
		return 0, err
	}

	if len(obfData) > 16384 {
		return 0, fmt.Errorf("packet too large: %d", len(obfData))
	}

	// Send length prefix
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(obfData)))
	if _, err := c.Conn.Write(lenBuf[:]); err != nil {
		return 0, err
	}

	// Send obfuscated data
	if _, err := c.Conn.Write(obfData); err != nil {
		return 0, err
	}

	return len(b), nil
}

// AWGProfile holds auto-generated AWG parameters
type AWGProfile struct {
	// Jc is the junk packet count
	Jc int

	// Jmin is the minimum junk packet size
	Jmin int

	// Jmax is the maximum junk packet size
	Jmax int

	// S1-S4 are junk packet timing parameters
	S1, S2, S3, S4 int

	// H1-H4 are header parameters
	H1, H2, H3, H4 uint32

	// I1-I15 are initialization parameters
	I1, I2, I3, I4, I5 int
}

// GenerateAWGProfile generates AWG parameters from session entropy
func GenerateAWGProfile(entropy []byte) *AWGProfile {
	// Derive parameters from entropy using SHA-256
	hash := sha256.Sum256(entropy)

	profile := &AWGProfile{}

	// Jc: 5-50 junk packets
	profile.Jc = 5 + int(hash[0])%45

	// Jmin: 50-500 bytes
	profile.Jmin = 50 + int(hash[1])%450

	// Jmax: Jmin to Jmin+2000 bytes
	profile.Jmax = profile.Jmin + 200 + int(hash[2])%1800

	// S1-S4: timing parameters (milliseconds)
	profile.S1 = 10 + int(hash[3])%90
	profile.S2 = 100 + int(hash[4])%400
	profile.S3 = 50 + int(hash[5])%150
	profile.S4 = 200 + int(hash[6])%800

	// H1-H4: header parameters
	profile.H1 = binary.BigEndian.Uint32(hash[8:12])
	profile.H2 = binary.BigEndian.Uint32(hash[12:16])
	profile.H3 = binary.BigEndian.Uint32(hash[16:20])
	profile.H4 = binary.BigEndian.Uint32(hash[20:24])

	// I1-I5: initialization parameters
	profile.I1 = int(hash[24]) % 2
	profile.I2 = int(hash[25]) % 2
	profile.I3 = int(hash[26]) % 2
	profile.I4 = int(hash[27]) % 100
	profile.I5 = int(hash[28]) % 100

	return profile
}

// JunkInjector injects junk packets for AWG-style obfuscation
type JunkInjector struct {
	// profile is the AWG profile
	profile *AWGProfile

	// interval is the injection interval
	interval time.Duration

	// conn is the connection to inject on
	conn net.Conn

	// stopCh signals the injector to stop
	stopCh chan struct{}

	// wg waits for the injector to stop
	wg sync.WaitGroup
}

// NewJunkInjector creates a new junk injector
func NewJunkInjector(profile *AWGProfile, interval time.Duration, conn net.Conn) *JunkInjector {
	return &JunkInjector{
		profile:  profile,
		interval: interval,
		conn:     conn,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the junk injector
func (j *JunkInjector) Start() {
	j.wg.Add(1)
	go j.injectLoop()
}

// Stop stops the junk injector
func (j *JunkInjector) Stop() {
	close(j.stopCh)
	j.wg.Wait()
}

// injectLoop is the main injection loop
func (j *JunkInjector) injectLoop() {
	defer j.wg.Done()

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			j.injectJunk()
		case <-j.stopCh:
			return
		}
	}
}

// junkFrameHeader is the magic byte indicating a junk/padding frame
const junkFrameMagic byte = 0xFF

// injectJunk injects a framed junk packet on the connection.
// Frame format: [magic(1)][length(2)][junk_data(length)]
func (j *JunkInjector) injectJunk() {
	// Generate random junk packet size between Jmin and Jmax
	size := j.profile.Jmin
	if j.profile.Jmax > j.profile.Jmin {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return
		}
		range_ := j.profile.Jmax - j.profile.Jmin
		size += int(binary.BigEndian.Uint32(b[:])) % range_
	}

	// Build framed junk packet: magic(1) + length(2) + data(size)
	frame := make([]byte, 3+size)
	frame[0] = junkFrameMagic
	binary.BigEndian.PutUint16(frame[1:3], uint16(size))

	// Fill with random data
	if _, err := rand.Read(frame[3:]); err != nil {
		return
	}

	// Send on the connection
	_, _ = j.conn.Write(frame)
}
