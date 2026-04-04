package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// Session represents a connected agent session.
type Session struct {
	Token     string     `json:"token"`
	RemoteAddr string   `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	Evidence  *Evidence  `json:"evidence,omitempty"`

	conn    net.Conn
	encoder *json.Encoder
	decoder *json.Decoder
	mu      sync.Mutex
}

// SendCommand sends a command to the agent and waits for a response.
func (s *Session) SendCommand(ctx context.Context, cmd string, args ...string) (*CommandResponse, error) {
	req := CommandRequest{Cmd: cmd, Args: args, Timeout: 30 * time.Second}
	payload, _ := json.Marshal(req)

	s.mu.Lock()
	err := s.encoder.Encode(Message{Type: "command", Payload: payload})
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send command: %w", err)
	}

	// Wait for response.
	var msg Message
	if err := s.decoder.Decode(&msg); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if msg.Type == "error" {
		return nil, fmt.Errorf("agent error: %s", string(msg.Payload))
	}
	if msg.Type != "command_response" {
		return nil, fmt.Errorf("unexpected message type: %s", msg.Type)
	}

	var resp CommandResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &resp, nil
}

// Close terminates the agent session.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encoder.Encode(Message{Type: "bye"}) //nolint:errcheck
	return s.conn.Close()
}

// Handler listens for incoming agent connections.
type Handler struct {
	listenAddr string
	tlsConfig  *tls.Config
	listener   net.Listener

	mu       sync.Mutex
	sessions map[string]*Session

	// OnConnect is called when an agent connects. May be nil.
	OnConnect func(session *Session)

	// OnEvidence is called when evidence is received. May be nil.
	OnEvidence func(session *Session, evidence *Evidence)
}

// NewHandler creates a handler that listens for agent connections.
// If tlsCert/tlsKey are empty, a self-signed certificate is generated.
func NewHandler(listenAddr string) (*Handler, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("generate cert: %w", err)
	}

	return &Handler{
		listenAddr: listenAddr,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		sessions: make(map[string]*Session),
	}, nil
}

// Start begins accepting agent connections.
func (h *Handler) Start(ctx context.Context) error {
	listener, err := tls.Listen("tcp", h.listenAddr, h.tlsConfig)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	h.listener = listener

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutting down
			}
			continue
		}
		go h.handleConnection(conn)
	}
}

// Stop closes the listener and all sessions.
func (h *Handler) Stop() {
	if h.listener != nil {
		_ = h.listener.Close()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sessions {
		_ = s.Close()
	}
}

// GetSession returns a session by token.
func (h *Handler) GetSession(token string) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[token]
}

// Sessions returns all active sessions.
func (h *Handler) Sessions() []*Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]*Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		result = append(result, s)
	}
	return result
}

func (h *Handler) handleConnection(conn net.Conn) {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	// Read hello message.
	var hello Message
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := decoder.Decode(&hello); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // clear deadline

	if hello.Type != "hello" {
		_ = conn.Close()
		return
	}

	// Validate token: must be non-empty, reasonable length, and not overwrite
	// an existing active session (prevents hijacking).
	if len(hello.Token) < 16 || len(hello.Token) > 256 {
		_ = conn.Close()
		return
	}

	h.mu.Lock()
	if existing, ok := h.sessions[hello.Token]; ok {
		h.mu.Unlock()
		// Reject connection that would overwrite an active session.
		_ = existing.conn.Close() // force-close stale connection if any
		_ = conn.Close()
		return
	}

	session := &Session{
		Token:       hello.Token,
		RemoteAddr:  conn.RemoteAddr().String(),
		ConnectedAt: time.Now().UTC(),
		conn:        conn,
		encoder:     encoder,
		decoder:     decoder,
	}
	h.sessions[session.Token] = session
	h.mu.Unlock()

	if h.OnConnect != nil {
		h.OnConnect(session)
	}

	// Read messages until the agent disconnects.
	// Set a read deadline to prevent slow-read attacks from keeping goroutines
	// alive indefinitely. Reset after each successful message.
	const idleTimeout = 5 * time.Minute
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		var msg Message
		if err := decoder.Decode(&msg); err != nil {
			break
		}

		switch msg.Type {
		case "evidence":
			var ev Evidence
			if err := json.Unmarshal(msg.Payload, &ev); err == nil {
				session.Evidence = &ev
				if h.OnEvidence != nil {
					h.OnEvidence(session, &ev)
				}
			}
		case "bye":
			return
		}
	}

	h.mu.Lock()
	delete(h.sessions, session.Token)
	h.mu.Unlock()
}

// generateSelfSignedCert creates an ephemeral TLS certificate for the handler.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "beacon-agent-handler"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf: &x509.Certificate{
			Raw: certDER,
		},
	}, nil
}
