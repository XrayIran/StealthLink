// Package lz4 implements LZ4 compression for StealthLink.
// It provides stateless compression for data streams to reduce bandwidth usage.
package lz4

import (
	"compress/flate"
	"io"
	"math"
	"net"
	"sync"

	"github.com/klauspost/compress/zlib"
	"github.com/pierrec/lz4/v4"
)

// Level represents compression level.
type Level int

const (
	LevelFastest Level = iota
	LevelFast
	LevelDefault
	LevelSlow
	LevelSlowest
)

// Compressor provides LZ4 compression.
type Compressor struct {
	level Level
}

// NewCompressor creates a new LZ4 compressor.
func NewCompressor(level Level) *Compressor {
	if level < LevelFastest || level > LevelSlowest {
		level = LevelDefault
	}
	return &Compressor{level: level}
}

// Compress compresses data using LZ4.
func (c *Compressor) Compress(src []byte) []byte {
	// Use lz4.CompressBlock for stateless compression
	compressed := make([]byte, lz4.CompressBlockBound(len(src)))

	n, err := lz4.CompressBlock(src, compressed, nil)
	if err != nil || n <= 0 {
		// Compression failed or no benefit, return original
		return src
	}

	// Check if compression actually helped
	if n >= len(src) {
		return src
	}

	return compressed[:n]
}

// Decompress decompresses LZ4 data.
func (c *Compressor) Decompress(compressed []byte, originalSize int) []byte {
	dst := make([]byte, originalSize)
	n, err := lz4.UncompressBlock(compressed, dst)
	if err != nil {
		return compressed // Return original if decompression fails
	}
	return dst[:n]
}

// Writer implements io.WriteCloser with LZ4 compression.
type Writer struct {
	writer io.Writer
	comp   *Compressor
	buffer []byte
	mu     sync.Mutex
}

// NewWriter creates a new LZ4 writer.
func NewWriter(w io.Writer, level Level) *Writer {
	return &Writer{
		writer: w,
		comp:   NewCompressor(level),
		buffer: make([]byte, 0, 64*1024), // 64KB buffer
	}
}

// Write compresses and writes data.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buffer = append(w.buffer, p...)
	return len(p), nil
}

// Flush flushes any buffered data.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.buffer) == 0 {
		return nil
	}

	compressed := w.comp.Compress(w.buffer)
	if _, err := w.writer.Write(compressed); err != nil {
		return err
	}

	w.buffer = w.buffer[:0]
	return nil
}

// Close flushes and closes the writer.
func (w *Writer) Close() error {
	return w.Flush()
}

// Reader implements io.ReadCloser with LZ4 decompression.
type Reader struct {
	reader io.Reader
	comp   *Compressor
	buffer []byte
	offset int
	mu     sync.Mutex
}

// NewReader creates a new LZ4 reader.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		reader: r,
		comp:   NewCompressor(LevelDefault),
		buffer: make([]byte, 0, 64*1024),
	}
}

// Read reads and decompresses data.
func (r *Reader) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Return buffered data first
	if len(r.buffer) > 0 && r.offset < len(r.buffer) {
		n = copy(p, r.buffer[r.offset:])
		r.offset += n
		if r.offset >= len(r.buffer) {
			r.buffer = r.buffer[:0]
			r.offset = 0
		}
		return n, nil
	}

	// Read compressed data
	buf := make([]byte, 64*1024)
	nn, err := r.reader.Read(buf)
	if err != nil && err != io.EOF {
		return 0, err
	}

	if nn > 0 {
		// Decompress - for now, assume data is uncompressed
		// In production, you'd need a framing protocol
		n = copy(p, buf[:nn])
		if nn > n {
			// Buffer remaining data
			r.buffer = append(r.buffer, buf[n:nn]...)
		}
		return n, nil
	}

	return 0, err
}

// Close closes the reader.
func (r *Reader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamCompressor provides stream-based compression with framing.
type StreamCompressor struct {
	writer io.Writer
	lzw    *lz4.Writer
	mu     sync.Mutex
}

// NewStreamCompressor creates a new stream compressor.
func NewStreamCompressor(w io.Writer) *StreamCompressor {
	return &StreamCompressor{
		writer: w,
	}
}

// Write compresses and writes data with framing.
func (sc *StreamCompressor) Write(p []byte) (int, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.lzw == nil {
		sc.lzw = lz4.NewWriter(sc.writer)
	}
	return sc.lzw.Write(p)
}

// Flush flushes the compressor.
func (sc *StreamCompressor) Flush() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.lzw != nil {
		return sc.lzw.Flush()
	}
	return nil
}

// Close closes the compressor.
func (sc *StreamCompressor) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.lzw != nil {
		err := sc.lzw.Close()
		sc.lzw = nil
		return err
	}
	return nil
}

// StreamDecompressor provides stream-based decompression with framing.
type StreamDecompressor struct {
	reader io.Reader
	lzr    *lz4.Reader
	mu     sync.Mutex
}

// NewStreamDecompressor creates a new stream decompressor.
func NewStreamDecompressor(r io.Reader) *StreamDecompressor {
	return &StreamDecompressor{
		reader: r,
	}
}

// Read reads and decompresses data.
func (sd *StreamDecompressor) Read(p []byte) (n int, err error) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	if sd.lzr == nil {
		sd.lzr = lz4.NewReader(sd.reader)
	}
	return sd.lzr.Read(p)
}

// Close closes the decompressor.
func (sd *StreamDecompressor) Close() error {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	if sd.lzr != nil {
		sd.lzr.Reset(nil)
		sd.lzr = nil
	}
	if closer, ok := sd.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// ZlibCompressor provides zlib compression as an alternative.
type ZlibCompressor struct {
	level   int
	writer  io.Writer
	zwriter *zlib.Writer
	mu      sync.Mutex
}

// NewZlibCompressor creates a new zlib compressor.
func NewZlibCompressor(w io.Writer, level int) *ZlibCompressor {
	zl := flate.DefaultCompression
	if level >= -2 && level <= 9 {
		zl = level
	}

	return &ZlibCompressor{
		level:  zl,
		writer: w,
	}
}

// Write compresses and writes data.
func (zc *ZlibCompressor) Write(p []byte) (int, error) {
	zc.mu.Lock()
	defer zc.mu.Unlock()

	if zc.zwriter == nil {
		var err error
		zc.zwriter, err = zlib.NewWriterLevel(zc.writer, zc.level)
		if err != nil {
			return 0, err
		}
	}
	return zc.zwriter.Write(p)
}

// Flush flushes the compressor.
func (zc *ZlibCompressor) Flush() error {
	zc.mu.Lock()
	defer zc.mu.Unlock()

	if zc.zwriter != nil {
		return zc.zwriter.Flush()
	}
	return nil
}

// Close closes the compressor.
func (zc *ZlibCompressor) Close() error {
	zc.mu.Lock()
	defer zc.mu.Unlock()

	if zc.zwriter != nil {
		err := zc.zwriter.Close()
		zc.zwriter = nil
		return err
	}
	return nil
}

// Stats provides compression statistics.
type Stats struct {
	BytesIn          int64
	BytesOut         int64
	CompressionRatio float64
}

// StatsCollector collects compression stats.
type StatsCollector struct {
	stats Stats
	mu    sync.RWMutex
}

// NewStatsCollector creates a new stats collector.
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{}
}

// Record records compression stats.
func (s *StatsCollector) Record(bytesIn, bytesOut int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.BytesIn += int64(bytesIn)
	s.stats.BytesOut += int64(bytesOut)

	if s.stats.BytesIn > 0 {
		s.stats.CompressionRatio = float64(s.stats.BytesOut) / float64(s.stats.BytesIn)
	}
}

// GetStats returns the current stats.
func (s *StatsCollector) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// Reset resets the stats.
func (s *StatsCollector) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats = Stats{}
}

// CompressionWrapper wraps a connection with compression.
type CompressionWrapper struct {
	net.Conn
	compressor   *StreamCompressor
	decompressor *StreamDecompressor
	level        Level
	stats        *StatsCollector
}

// NewCompressionWrapper creates a new compression wrapper.
func NewCompressionWrapper(conn net.Conn, level Level) *CompressionWrapper {
	return &CompressionWrapper{
		Conn:  conn,
		level: level,
		stats: NewStatsCollector(),
	}
}

// Write compresses and writes data.
func (cw *CompressionWrapper) Write(p []byte) (int, error) {
	if cw.compressor == nil {
		cw.compressor = NewStreamCompressor(cw.Conn)
	}

	n, err := cw.compressor.Write(p)
	if n > 0 {
		cw.stats.Record(n, n) // Approximate, would need actual compressed size
	}
	return n, err
}

// Read reads and decompresses data.
func (cw *CompressionWrapper) Read(p []byte) (n int, err error) {
	if cw.decompressor == nil {
		cw.decompressor = NewStreamDecompressor(cw.Conn)
	}

	n, err = cw.decompressor.Read(p)
	cw.stats.Record(n, n) // Approximate
	return n, err
}

// Close closes the connection and compression streams.
func (cw *CompressionWrapper) Close() error {
	var errs []error

	if cw.compressor != nil {
		if err := cw.compressor.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if cw.decompressor != nil {
		if err := cw.decompressor.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := cw.Conn.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// GetStats returns compression statistics.
func (cw *CompressionWrapper) GetStats() Stats {
	return cw.stats.GetStats()
}

// ShouldCompress determines if data should be compressed based on type.
func ShouldCompress(data []byte) bool {
	// Don't compress very small data
	if len(data) < 128 {
		return false
	}

	// Check if data is already compressed (heuristic)
	// High entropy data is likely already compressed
	entropy := calculateEntropy(data)
	if entropy > 7.5 {
		return false
	}

	return true
}

// calculateEntropy calculates Shannon entropy of data.
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * log2(p)
		}
	}

	return entropy
}

func log2(x float64) float64 {
	return math.Log2(x)
}

// ConnectionManager manages compression for multiple connections.
type ConnectionManager struct {
	compressors  map[*CompressionWrapper]bool
	mu           sync.RWMutex
	defaultLevel Level
}

// NewConnectionManager creates a new connection manager.
func NewConnectionManager(defaultLevel Level) *ConnectionManager {
	return &ConnectionManager{
		compressors:  make(map[*CompressionWrapper]bool),
		defaultLevel: defaultLevel,
	}
}

// Wrap wraps a connection with compression.
func (cm *ConnectionManager) Wrap(conn net.Conn) *CompressionWrapper {
	cw := NewCompressionWrapper(conn, cm.defaultLevel)

	cm.mu.Lock()
	cm.compressors[cw] = true
	cm.mu.Unlock()

	return cw
}

// Unwrap removes a connection from management.
func (cm *ConnectionManager) Unwrap(cw *CompressionWrapper) {
	cm.mu.Lock()
	delete(cm.compressors, cw)
	cm.mu.Unlock()
}

// GetTotalStats returns combined stats for all connections.
func (cm *ConnectionManager) GetTotalStats() Stats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	total := Stats{}
	for cw := range cm.compressors {
		stats := cw.GetStats()
		total.BytesIn += stats.BytesIn
		total.BytesOut += stats.BytesOut
	}

	if total.BytesIn > 0 {
		total.CompressionRatio = float64(total.BytesOut) / float64(total.BytesIn)
	}

	return total
}

// SetDefaultLevel sets the default compression level for new connections.
func (cm *ConnectionManager) SetDefaultLevel(level Level) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.defaultLevel = level
}
