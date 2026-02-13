package reality

import (
	"context"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
	"golang.org/x/net/html"
)

// SpiderConfig defines spider behavior
type SpiderConfig struct {
	Enabled         bool          `yaml:"enabled"`
	SpiderX         string        `yaml:"spider_x"`          // initial URL seed
	SpiderY         [10]int       `yaml:"spider_y"`          // timing array in milliseconds
	Concurrency     int           `yaml:"spider_concurrency"` // default: 4
	Timeout         time.Duration `yaml:"spider_timeout"`      // default: 10s
	MaxDepth        int           `yaml:"max_depth"`         // default: 3
	MaxTotalFetches int           `yaml:"max_total_fetches"`  // default: 20
	PerHostCap      int           `yaml:"per_host_cap"`       // default: 5
}

// DefaultSpiderConfig returns the default spider configuration
func DefaultSpiderConfig() SpiderConfig {
	return SpiderConfig{
		Enabled:         false,
		SpiderY:         [10]int{50, 100, 200, 300, 500, 800, 1000, 1500, 2000, 3000},
		Concurrency:     4,
		Timeout:         10 * time.Second,
		MaxDepth:        3,
		MaxTotalFetches: 20,
		PerHostCap:      5,
	}
}

// Spider manages concurrent web crawling for REALITY.
type Spider struct {
	config    SpiderConfig
	queue     chan *crawlItem
	visited   *sync.Map // URL -> bool
	hostCount *sync.Map // host -> count
	fetches   atomic.Int32
	client    *http.Client
	wg        sync.WaitGroup
	startTime time.Time
}

type crawlItem struct {
	url   string
	depth int
}

// NewSpider creates a new REALITY spider.
func NewSpider(config SpiderConfig) *Spider {
	if config.Concurrency <= 0 {
		config.Concurrency = 4
	}
	if config.MaxDepth <= 0 {
		config.MaxDepth = 3
	}
	if config.MaxTotalFetches <= 0 {
		config.MaxTotalFetches = 20
	}
	if config.PerHostCap <= 0 {
		config.PerHostCap = 5
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	return &Spider{
		config:    config,
		queue:     make(chan *crawlItem, 1000),
		visited:   &sync.Map{},
		hostCount: &sync.Map{},
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Start launches the spider.
func (s *Spider) Start(ctx context.Context) error {
	if !s.config.Enabled || s.config.SpiderX == "" {
		return nil
	}

	s.startTime = time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// Initial seed
	s.queue <- &crawlItem{url: s.config.SpiderX, depth: 0}
	metrics.IncRealitySpiderURLsCrawled()

	// Launch workers
	for i := 0; i < s.config.Concurrency; i++ {
		s.wg.Add(1)
		go s.crawlWorker(ctx, i)
	}

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	metrics.AddRealitySpiderDuration(time.Since(s.startTime))
	return nil
}

func (s *Spider) crawlWorker(ctx context.Context, id int) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case item := <-s.queue:
			metrics.DecRealitySpiderURLsCrawled()
			
			if s.fetches.Load() >= int32(s.config.MaxTotalFetches) {
				return
			}

			if !s.shouldCrawl(item) {
				continue
			}

			s.applyTiming(int(s.fetches.Load()))
			s.fetch(ctx, item)
			
			if s.fetches.Load() >= int32(s.config.MaxTotalFetches) {
				return
			}
		default:
			// Queue empty or all workers busy
			// In a real spider we might wait a bit, but here we can exit if no one is fetching
			time.Sleep(100 * time.Millisecond)
			if len(s.queue) == 0 {
				return
			}
		}
	}
}

func (s *Spider) shouldCrawl(item *crawlItem) bool {
	if item.depth > s.config.MaxDepth {
		return false
	}

	u, err := url.Parse(item.url)
	if err != nil {
		return false
	}

	// Normalize URL
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	normalizedURL := u.String()

	// Check visited
	if _, loaded := s.visited.LoadOrStore(normalizedURL, true); loaded {
		return false
	}

	// Check per-host cap
	v, _ := s.hostCount.LoadOrStore(u.Host, new(int32))
	if atomic.AddInt32(v.(*int32), 1) > int32(s.config.PerHostCap) {
		return false
	}

	return true
}

func (s *Spider) applyTiming(fetchNum int) {
	delayMs := s.config.SpiderY[9]
	if fetchNum < 10 {
		delayMs = s.config.SpiderY[fetchNum]
	}

	// Add ±10% jitter
	jitter := float64(delayMs) * 0.1
	actualDelay := float64(delayMs) - jitter + rand.Float64()*2*jitter

	time.Sleep(time.Duration(actualDelay) * time.Millisecond)
}

func (s *Spider) fetch(ctx context.Context, item *crawlItem) {
	req, err := http.NewRequestWithContext(ctx, "GET", item.url, nil)
	if err != nil {
		return
	}

	// Mimic browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	s.fetches.Add(1)
	metrics.IncRealitySpiderFetch()

	if resp.StatusCode != http.StatusOK {
		return
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return
	}

	s.extractLinks(resp.Body, item.url, item.depth)
}

func (s *Spider) extractLinks(body io.Reader, baseURL string, depth int) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	z := html.NewTokenizer(body)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == "a" {
				for _, a := range t.Attr {
					if a.Key == "href" {
						linkURL, err := url.Parse(a.Val)
						if err != nil {
							continue
						}
						
						absoluteURL := u.ResolveReference(linkURL)
						if absoluteURL.Scheme == "http" || absoluteURL.Scheme == "https" {
							select {
							case s.queue <- &crawlItem{url: absoluteURL.String(), depth: depth + 1}:
								metrics.IncRealitySpiderURLsCrawled()
							default:
								// Queue full
							}
						}
					}
				}
			}
		}
	}
}
