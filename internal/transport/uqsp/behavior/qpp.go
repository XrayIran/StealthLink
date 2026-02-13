package behavior

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"stealthlink/internal/config"
)

const (
	qppBlockSize   = 16
	qppTableSize   = 256
	qppNumTables   = 8
	qppHeaderMagic = 0x51505031
)

type QPPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Key      string `yaml:"key"`
	Seed     []byte `yaml:"seed"`
	NumSBox  int    `yaml:"num_sbox"`
	AutoSync bool   `yaml:"auto_sync"`
}

type QPPOverlay struct {
	EnabledField bool
	Config       QPPConfig

	encryptTables [qppNumTables][]byte
	decryptTables [qppNumTables][]byte
	mu            sync.Mutex
	initialized   bool
}

func NewQPPOverlay(cfg config.QPPBehaviorConfig) *QPPOverlay {
	o := &QPPOverlay{
		EnabledField: cfg.Enabled,
		Config: QPPConfig{
			Enabled:  cfg.Enabled,
			Key:      cfg.Key,
			NumSBox:  cfg.NumSBox,
			AutoSync: cfg.AutoSync,
		},
	}

	if cfg.NumSBox <= 0 {
		o.Config.NumSBox = qppNumTables
	}

	if cfg.Enabled && cfg.Key != "" {
		o.initTables([]byte(cfg.Key))
	}

	return o
}

func (o *QPPOverlay) initTables(key []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()

	seed := sha256.Sum256(key)

	for t := 0; t < qppNumTables; t++ {
		o.encryptTables[t] = make([]byte, qppTableSize)
		o.decryptTables[t] = make([]byte, qppTableSize)

		for i := 0; i < qppTableSize; i++ {
			o.encryptTables[t][i] = byte(i)
		}

		seedHash := sha256.Sum256(append(seed[:], byte(t)))
		o.permute(o.encryptTables[t], seedHash[:])

		for i := 0; i < qppTableSize; i++ {
			o.decryptTables[t][o.encryptTables[t][i]] = byte(i)
		}
	}

	o.initialized = true
}

func (o *QPPOverlay) permute(table []byte, seed []byte) {
	n := len(table)
	for i := n - 1; i > 0; i-- {
		j := int(seed[i%len(seed)]) % (i + 1)
		table[i], table[j] = table[j], table[i]
	}
}

func (o *QPPOverlay) Name() string {
	return "qpp"
}

func (o *QPPOverlay) Enabled() bool {
	return o.EnabledField
}

func (o *QPPOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	if !o.initialized && o.Config.Key != "" {
		o.initTables([]byte(o.Config.Key))
	}

	if !o.initialized {
		return nil, fmt.Errorf("qpp not initialized: key required")
	}

	return &qppConn{
		Conn:    conn,
		overlay: o,
	}, nil
}

func (o *QPPOverlay) Encrypt(data []byte) []byte {
	if !o.initialized {
		return data
	}

	result := make([]byte, len(data))
	for i, b := range data {
		tableIdx := i % qppNumTables
		result[i] = o.encryptTables[tableIdx][b]
	}
	return result
}

func (o *QPPOverlay) Decrypt(data []byte) []byte {
	if !o.initialized {
		return data
	}

	result := make([]byte, len(data))
	for i, b := range data {
		tableIdx := i % qppNumTables
		result[i] = o.decryptTables[tableIdx][b]
	}
	return result
}

type qppConn struct {
	net.Conn
	overlay *QPPOverlay
	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func (c *qppConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}

	frameLen := int(binary.BigEndian.Uint32(header))
	if frameLen < 0 || frameLen > 1<<20 {
		return 0, fmt.Errorf("qpp: invalid frame length %d", frameLen)
	}

	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, ciphertext); err != nil {
		return 0, err
	}

	plaintext := c.overlay.Decrypt(ciphertext)
	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = append(c.readBuf[:0], plaintext[n:]...)
	}
	return n, nil
}

func (c *qppConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	encrypted := c.overlay.Encrypt(p)

	frame := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(encrypted)))
	copy(frame[4:], encrypted)

	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *qppConn) Close() error {
	return c.Conn.Close()
}

type QPPKeyExchange struct {
	PublicKey  []byte
	PrivateKey []byte
}

func GenerateQPPKey() *QPPKeyExchange {
	priv := make([]byte, 32)
	rand.Read(priv)
	pub := sha256.Sum256(priv)

	return &QPPKeyExchange{
		PublicKey:  pub[:],
		PrivateKey: priv,
	}
}

func DeriveQPPKey(privateKey, peerPublicKey []byte) []byte {
	combined := append(privateKey, peerPublicKey...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

type QPPStreamEncoder struct {
	overlay   *QPPOverlay
	blockMode bool
	blockSize int
}

func NewQPPStreamEncoder(overlay *QPPOverlay, blockSize int) *QPPStreamEncoder {
	if blockSize <= 0 {
		blockSize = qppBlockSize
	}
	return &QPPStreamEncoder{
		overlay:   overlay,
		blockMode: true,
		blockSize: blockSize,
	}
}

func (e *QPPStreamEncoder) EncodeStream(r io.Reader, w io.Writer) error {
	buf := make([]byte, e.blockSize)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n > 0 {
			encoded := e.overlay.Encrypt(buf[:n])
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(len(encoded)))
			if _, werr := w.Write(lenBuf); werr != nil {
				return werr
			}
			if _, werr := w.Write(encoded); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func (e *QPPStreamEncoder) DecodeStream(r io.Reader, w io.Writer) error {
	lenBuf := make([]byte, 2)
	for {
		_, err := io.ReadFull(r, lenBuf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		encLen := int(binary.BigEndian.Uint16(lenBuf))
		encBuf := make([]byte, encLen)
		if _, err := io.ReadFull(r, encBuf); err != nil {
			return err
		}

		decoded := e.overlay.Decrypt(encBuf)
		if _, err := w.Write(decoded); err != nil {
			return err
		}
	}
}
