// Package multiport provides a dialer that can connect to multiple ports
// simultaneously and use the first successful connection.
package multiport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Dialer dials multiple ports in parallel and returns the first successful connection.
type Dialer struct {
	Ports    []int           // List of ports to try
	Parallel int             // Max parallel dials (0 = unlimited)
	Timeout  time.Duration   // Timeout for each dial attempt
	Dialer   *net.Dialer     // Underlying dialer (optional)
}

// NewDialer creates a new multiport dialer.
func NewDialer(ports []int) *Dialer {
	return &Dialer{
		Ports:    ports,
		Parallel: 0, // Unlimited by default
		Timeout:  10 * time.Second,
	}
}

// Dial attempts to connect to the host on multiple ports in parallel.
// It returns the first successful connection.
func (d *Dialer) Dial(ctx context.Context, host string) (net.Conn, error) {
	if len(d.Ports) == 0 {
		return nil, fmt.Errorf("no ports configured")
	}

	// If only one port, just dial directly
	if len(d.Ports) == 1 {
		return d.dialSingle(ctx, host, d.Ports[0])
	}

	// Create a context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	// Result channel
	type result struct {
		conn net.Conn
		err  error
		port int
	}
	resultCh := make(chan result, len(d.Ports))

	// Semaphore for limiting parallelism
	var sem chan struct{}
	if d.Parallel > 0 {
		sem = make(chan struct{}, d.Parallel)
	}

	// Start all dial attempts
	var wg sync.WaitGroup
	for _, port := range d.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Acquire semaphore if limited
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-dialCtx.Done():
					return
				}
			}

			conn, err := d.dialSingle(dialCtx, host, p)
			select {
			case resultCh <- result{conn, err, p}:
			case <-dialCtx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}(port)
	}

	// Close result channel when all dials complete
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	var firstConn net.Conn
	var firstErr error
	var successPort int

	for res := range resultCh {
		if res.err == nil && firstConn == nil {
			firstConn = res.conn
			successPort = res.port
			// Cancel remaining dials
			cancel()
		} else if res.err != nil && firstErr == nil {
			firstErr = res.err
		} else if firstConn != nil && res.conn != nil {
			// Close extra successful connections
			_ = res.conn.Close()
		}
	}

	if firstConn == nil {
		if firstErr != nil {
			return nil, fmt.Errorf("all dial attempts failed: %w", firstErr)
		}
		return nil, fmt.Errorf("all dial attempts failed")
	}

	return &connWithPort{Conn: firstConn, port: successPort}, nil
}

// dialSingle dials a single port.
func (d *Dialer) dialSingle(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	return dialer.DialContext(ctx, "tcp", addr)
}

// connWithPort wraps a connection and records which port was used.
type connWithPort struct {
	net.Conn
	port int
}

// Port returns the port that was successfully connected to.
func (c *connWithPort) Port() int {
	return c.port
}

// MultiAddr is a net.Addr that includes the port information.
type MultiAddr struct {
	net.Addr
	Port int
}

// ParsePortRange parses a port range string like "1000-1005" or "1000,1002,1004".
func ParsePortRange(s string) ([]int, error) {
	var ports []int

	// Try parsing as range first
	var start, end int
	if _, err := fmt.Sscanf(s, "%d-%d", &start, &end); err == nil {
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
		return ports, nil
	}

	// Try parsing as comma-separated list
	var port int
	for _, err := fmt.Sscanf(s, "%d", &port); err == nil; {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %d", port)
		}
		ports = append(ports, port)
		// Remove the parsed port from string
		for i := 0; i < len(s); i++ {
			if s[i] == ',' {
				s = s[i+1:]
				break
			}
			if i == len(s)-1 {
				s = ""
			}
		}
		_, err = fmt.Sscanf(s, "%d", &port)
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports found in: %s", s)
	}

	return ports, nil
}

// CommonPortRanges provides common port ranges for different use cases.
func CommonPortRanges() map[string][]int {
	return map[string][]int{
		"http":       {80, 8080, 8000, 8888},
		"https":      {443, 8443, 9443},
		"ssh":        {22, 2222, 8022},
		"dns":        {53, 5353},
		"ntp":        {123},
		"dhcp":       {67, 68},
		"high":       {10000, 10001, 10002, 10003, 10004},
		"ephemeral":  {49152, 49153, 49154, 49155, 49156},
	}
}

// RandomPort returns a random port from the configured range.
func (d *Dialer) RandomPort() int {
	if len(d.Ports) == 0 {
		return 0
	}
	return d.Ports[time.Now().UnixNano()%int64(len(d.Ports))]
}

// NextPort returns the next port in round-robin fashion.
func (d *Dialer) NextPort() int {
	if len(d.Ports) == 0 {
		return 0
	}
	idx := time.Now().UnixNano() % int64(len(d.Ports))
	return d.Ports[idx]
}
