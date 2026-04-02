// Package oob provides an out-of-band (OOB) callback server for blind
// vulnerability confirmation. Scanners generate unique tokens and embed them
// in payloads (e.g., JNDI lookups, DNS queries, HTTP requests). When the
// vulnerable target resolves/fetches the token URL, the OOB server records
// the callback, confirming the vulnerability.
//
// The server listens on HTTP (and optionally DNS) in-process. It works
// air-gapped — no external infrastructure like Interactsh needed.
//
// Usage:
//
//	srv := oob.NewServer("oob.example.com", ":8443")
//	srv.Start(ctx)
//	defer srv.Stop()
//
//	token := srv.GenerateToken("sqli-probe-1")
//	// embed token in payload: ${jndi:ldap://TOKEN.oob.example.com/a}
//	// or: nslookup TOKEN.oob.example.com
//	// or: curl http://oob.example.com:8443/TOKEN
//
//	callback, ok := srv.WaitForCallback(ctx, token, 10*time.Second)
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Callback records a single OOB interaction from a vulnerable target.
type Callback struct {
	Token      string    // the unique token that was triggered
	RemoteAddr string    // source IP of the callback
	Protocol   string    // "http" or "dns"
	Detail     string    // HTTP path or DNS query name
	ReceivedAt time.Time // when the callback arrived
}

// Server is an in-process OOB callback server.
type Server struct {
	domain     string // e.g., "oob.example.com"
	listenAddr string // e.g., ":8443"

	mu        sync.RWMutex
	tokens    map[string]string    // token → label
	callbacks map[string]*Callback // token → first callback
	waiters   map[string][]chan *Callback

	httpServer *http.Server
	dnsConn    *net.UDPConn
	done       chan struct{}
}

// NewServer creates an OOB server. domain is used for DNS-based callbacks.
// listenAddr is the HTTP listen address (e.g., ":8443" or "0.0.0.0:9999").
func NewServer(domain, listenAddr string) *Server {
	s := &Server{
		domain:     domain,
		listenAddr: listenAddr,
		tokens:     make(map[string]string),
		callbacks:  make(map[string]*Callback),
		waiters:    make(map[string][]chan *Callback),
		done:       make(chan struct{}),
	}
	return s
}

// Start begins listening for HTTP callbacks. Call Stop() to shut down.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHTTP)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s.httpServer = &http.Server{
		Addr:              s.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("oob: listen %s: %w", s.listenAddr, err)
	}

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			// Server error — log but don't crash
		}
	}()

	return nil
}

// StartDNS begins listening for DNS callbacks on the given UDP address (e.g., ":5353").
// This is optional — HTTP callbacks work without DNS.
func (s *Server) StartDNS(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("oob dns: resolve %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("oob dns: listen %s: %w", addr, err)
	}
	s.dnsConn = conn

	go s.serveDNS()
	return nil
}

// Stop shuts down the HTTP and DNS servers. Safe to call multiple times.
func (s *Server) Stop() {
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return // already stopped
	default:
		close(s.done)
	}
	s.mu.Unlock()

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(ctx)
	}
	if s.dnsConn != nil {
		_ = s.dnsConn.Close()
	}
}

// GenerateToken creates a unique token associated with the given label.
// The label identifies which probe/scanner generated the token.
func (s *Server) GenerateToken(label string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.tokens[token] = label
	s.mu.Unlock()

	return token
}

// CallbackURL returns the full URL a payload should call back to.
func (s *Server) CallbackURL(token string) string {
	return fmt.Sprintf("http://%s%s/%s", s.domain, s.listenAddr, token)
}

// DNSHostname returns the DNS name a payload should resolve.
func (s *Server) DNSHostname(token string) string {
	return token + "." + s.domain
}

// WaitForCallback blocks until the token receives a callback or the timeout expires.
// Returns the callback and true if received, or nil and false on timeout.
func (s *Server) WaitForCallback(ctx context.Context, token string, timeout time.Duration) (*Callback, bool) {
	// Check if already received
	s.mu.RLock()
	if cb, ok := s.callbacks[token]; ok {
		s.mu.RUnlock()
		return cb, true
	}
	s.mu.RUnlock()

	// Register a waiter channel
	ch := make(chan *Callback, 1)
	s.mu.Lock()
	s.waiters[token] = append(s.waiters[token], ch)
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case cb := <-ch:
		return cb, true
	case <-ctx.Done():
		return nil, false
	case <-s.done:
		return nil, false
	}
}

// GetCallback returns the callback for a token if one has been received.
func (s *Server) GetCallback(token string) (*Callback, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cb, ok := s.callbacks[token]
	return cb, ok
}

// recordCallback stores the callback and notifies any waiters.
func (s *Server) recordCallback(cb *Callback) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only record the first callback per token
	if _, exists := s.callbacks[cb.Token]; exists {
		return
	}

	// Verify token was registered
	if _, known := s.tokens[cb.Token]; !known {
		return
	}

	s.callbacks[cb.Token] = cb

	// Notify waiters
	for _, ch := range s.waiters[cb.Token] {
		select {
		case ch <- cb:
		default:
		}
	}
	delete(s.waiters, cb.Token)
}

// handleHTTP processes HTTP callbacks. The token is extracted from the URL path.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract token from path: /TOKEN or /TOKEN/anything
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	token := parts[0]

	if token == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s.recordCallback(&Callback{
		Token:      token,
		RemoteAddr: r.RemoteAddr,
		Protocol:   "http",
		Detail:     r.URL.Path,
		ReceivedAt: time.Now(),
	})

	w.WriteHeader(http.StatusOK)
}

// serveDNS handles incoming DNS queries, extracting tokens from subdomains.
// Minimal DNS implementation — only responds to A queries with 127.0.0.1.
func (s *Server) serveDNS() {
	buf := make([]byte, 512)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		_ = s.dnsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := s.dnsConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 12 {
			continue
		}

		// Parse the query name from the DNS packet (minimal parsing)
		qname := parseDNSQueryName(buf[12:n])
		if qname == "" {
			continue
		}

		// Extract token: TOKEN.oob.example.com → TOKEN
		token := extractTokenFromDNS(qname, s.domain)
		if token != "" {
			s.recordCallback(&Callback{
				Token:      token,
				RemoteAddr: remoteAddr.String(),
				Protocol:   "dns",
				Detail:     qname,
				ReceivedAt: time.Now(),
			})
		}

		// Send a minimal A record response (127.0.0.1)
		resp := buildDNSResponse(buf[:n])
		if resp != nil {
			_, _ = s.dnsConn.WriteToUDP(resp, remoteAddr)
		}
	}
}

// parseDNSQueryName extracts the query name from a DNS question section.
func parseDNSQueryName(data []byte) string {
	var labels []string
	i := 0
	for i < len(data) {
		length := int(data[i])
		if length == 0 {
			break
		}
		i++
		if i+length > len(data) {
			return ""
		}
		labels = append(labels, string(data[i:i+length]))
		i += length
	}
	return strings.Join(labels, ".")
}

// extractTokenFromDNS pulls the token prefix from a DNS name.
// e.g., "abc123.oob.example.com" with domain "oob.example.com" → "abc123"
func extractTokenFromDNS(qname, domain string) string {
	qname = strings.TrimSuffix(strings.ToLower(qname), ".")
	domain = strings.ToLower(domain)
	suffix := "." + domain
	if !strings.HasSuffix(qname, suffix) {
		return ""
	}
	token := qname[:len(qname)-len(suffix)]
	// Token should not contain dots (single-label prefix)
	if strings.Contains(token, ".") {
		return ""
	}
	return token
}

// buildDNSResponse creates a minimal DNS A record response pointing to 127.0.0.1.
func buildDNSResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	// Copy the query and modify header flags
	resp := make([]byte, len(query)+16)
	copy(resp, query)

	// Set QR bit (response), copy opcode, set AA bit
	resp[2] = 0x84 // QR=1, AA=1
	resp[3] = 0x00 // RCODE=0 (no error)

	// Set ANCOUNT to 1
	resp[6] = 0x00
	resp[7] = 0x01

	// Append answer: name pointer + type A + class IN + TTL 60 + rdlength 4 + 127.0.0.1
	answerOffset := len(query)
	resp[answerOffset] = 0xC0   // name pointer
	resp[answerOffset+1] = 0x0C // offset to question name
	resp[answerOffset+2] = 0x00 // type A
	resp[answerOffset+3] = 0x01
	resp[answerOffset+4] = 0x00 // class IN
	resp[answerOffset+5] = 0x01
	resp[answerOffset+6] = 0x00 // TTL
	resp[answerOffset+7] = 0x00
	resp[answerOffset+8] = 0x00
	resp[answerOffset+9] = 0x3C // 60 seconds
	resp[answerOffset+10] = 0x00 // rdlength
	resp[answerOffset+11] = 0x04
	resp[answerOffset+12] = 127 // 127.0.0.1
	resp[answerOffset+13] = 0
	resp[answerOffset+14] = 0
	resp[answerOffset+15] = 1

	return resp[:answerOffset+16]
}
