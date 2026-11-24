// Package collector is the OOB HTTP/HTTPS interaction server plus the local
// correlation API consumed by the scanner.
//
// Endpoints:
//
//	GET /p/<token>           marker page (synchronous SSRF detection)
//	GET /r/<token>?hops=&to= controlled redirect chain
//	ANY /<anything>          still logged if a token can be extracted
//	GET /api/events?token=   events for one token   (X-API-Key)
//	GET /api/events/since?seq=&limit=  tail events   (X-API-Key)
//	GET /healthz
package collector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ssrf-platform/internal/store"
	"ssrf-platform/internal/token"
	"ssrf-platform/internal/types"
)

// RebindRegistrar is implemented by the DNS server; the collector exposes it
// over the authenticated API so the scanner can arm rebind plans remotely.
type RebindRegistrar interface {
	RegisterPlan(token, publicIP string, internalIPs []string, ttl uint32) error
}

// Config configures the collector.
type Config struct {
	Domain                 string // apex OOB domain
	Secret                 []byte
	Store                  *store.Store
	APIKey                 string // shared secret for /api; empty disables the API
	AllowIntranetRedirects bool   // whether /r may redirect off the OOB domain
	BodyCaptureLimit       int64
	Rebind                 RebindRegistrar
}

// Server wraps an http.Server for plaintext and TLS.
type Server struct {
	cfg    Config
	store  *store.Store
	domain string
	http   *http.Server
	https  *http.Server
}

const markerPrefix = "SSRF-PLATFORM-MARKER:"

// New builds the handler and servers (not yet listening).
func New(cfg Config) *Server {
	if cfg.BodyCaptureLimit <= 0 {
		cfg.BodyCaptureLimit = 4096
	}
	s := &Server{
		cfg:    cfg,
		store:  cfg.Store,
		domain: strings.TrimSuffix(strings.ToLower(cfg.Domain), "."),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/api/events", s.handleAPI)
	mux.HandleFunc("/api/events/since", s.handleAPISince)
	mux.HandleFunc("/api/rebind", s.handleRebind)
	mux.HandleFunc("/", s.handleInteraction)
	handler := s.logging(mux)
	s.http = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	s.https = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	return s
}

// ListenAndServe starts HTTP (and HTTPS when tlsCfg is non-nil) listeners.
func (s *Server) ListenAndServe(httpAddr string, tlsCfg *tls.Config, httpsAddr string) error {
	errCh := make(chan error, 2)
	go func() {
		ln, err := net.Listen("tcp", httpAddr)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- s.http.Serve(ln)
	}()
	if tlsCfg != nil {
		go func() {
			ln, err := net.Listen("tcp", httpsAddr)
			if err != nil {
				errCh <- err
				return
			}
			s.https.TLSConfig = tlsCfg
			errCh <- s.https.Serve(tls.NewListener(ln, tlsCfg))
		}()
	}
	return <-errCh
}

// ServeHTTP serves plaintext HTTP on an existing listener (used by tests and
// custom socket deployments).
func (s *Server) ServeHTTP(ln net.Listener) error { return s.http.Serve(ln) }

// ServeHTTPS serves TLS on an existing listener with the given config.
func (s *Server) ServeHTTPS(ln net.Listener, tlsCfg *tls.Config) error {
	s.https.TLSConfig = tlsCfg
	return s.https.Serve(tls.NewListener(ln, tlsCfg))
}

// Close shuts both servers down.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var first error
	if err := s.http.Shutdown(ctx); err != nil && first == nil {
		first = err
	}
	if err := s.https.Shutdown(ctx); err != nil && first == nil {
		first = err
	}
	return first
}

func (s *Server) authOK(r *http.Request) bool {
	return s.cfg.APIKey != "" && r.Header.Get("X-API-Key") == s.cfg.APIKey
}

type rebindRequest struct {
	Token       string   `json:"token"`
	PublicIP    string   `json:"public_ip"`
	InternalIPs []string `json:"internal_ips"`
	TTL         uint32   `json:"ttl"`
}

func (s *Server) handleRebind(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.cfg.Rebind == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "dns rebind not configured"})
		return
	}
	var req rebindRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Token == "" || req.PublicIP == "" || len(req.InternalIPs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token, public_ip and internal_ips are required"})
		return
	}
	if err := s.cfg.Rebind.RegisterPlan(req.Token, req.PublicIP, req.InternalIPs, req.TTL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "armed"})
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tok := r.URL.Query().Get("token")
	evs, err := s.store.Lookup(tok)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, evs)
}

func (s *Server) handleAPISince(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	seq := uint64(0)
	if v := q.Get("seq"); v != "" {
		fmt.Sscan(v, &seq)
	}
	limit := 500
	fmt.Sscan(q.Get("limit"), &limit)
	writeJSON(w, http.StatusOK, s.store.Since(seq, limit))
}

// handleInteraction records every request and either serves a marker page or
// walks a controlled redirect chain.
func (s *Server) handleInteraction(w http.ResponseWriter, r *http.Request) {
	tok, ctx, trusted := s.extractToken(r)
	ev := s.buildEvent(r, tok, trusted)

	switch {
	case strings.HasPrefix(r.URL.Path, "/r/"):
		hops := uint(0)
		fmt.Sscan(r.URL.Query().Get("hops"), &hops)
		if hops > 0 {
			q := url.Values{}
			q.Set("hops", fmt.Sprintf("%d", hops-1))
			if to := r.URL.Query().Get("to"); to != "" {
				q.Set("to", to)
			}
			ev.Hops = int(hops)
			s.record(ev, ctx, trusted)
			http.Redirect(w, r, "/r/"+tok+"?"+q.Encode(), http.StatusFound)
			return
		}
		if to := r.URL.Query().Get("to"); to != "" && s.redirectAllowed(to) {
			ev.Hops = int(hops)
			ev.Marker = "redirect-final:" + to
			s.record(ev, ctx, trusted)
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		// Chain exhausted without an external target: fall through to marker.
	case strings.HasPrefix(r.URL.Path, "/p/"):
	}

	ev.Marker = markerPrefix + tok
	s.record(ev, ctx, trusted)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s\nssrf-platform interaction endpoint\ntoken=%s\n", markerPrefix+tok, tok)
}

func (s *Server) redirectAllowed(target string) bool {
	if !s.cfg.AllowIntranetRedirects {
		u, err := url.Parse(target)
		if err != nil {
			return false
		}
		host := strings.ToLower(u.Hostname())
		return host == s.domain || strings.HasSuffix(host, "."+s.domain)
	}
	return true
}

// extractToken resolves the token from the path first, then from subdomain
// labels of the OOB domain.
func (s *Server) extractToken(r *http.Request) (string, types.JobContext, bool) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && (parts[0] == "p" || parts[0] == "r") {
		flat, ctx, trusted := token.DecodeOrRaw(parts[1], s.cfg.Secret)
		return flat, ctx, trusted
	}
	host := strings.ToLower(strings.TrimSuffix(r.Host, "."))
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	if strings.HasSuffix(host, "."+s.domain) {
		prefix := strings.TrimSuffix(host, "."+s.domain)
		flat := strings.ReplaceAll(prefix, ".", "")
		_, ctx, trusted := token.DecodeOrRaw(flat, s.cfg.Secret)
		return flat, ctx, trusted
	}
	return "", types.JobContext{}, false
}

func (s *Server) buildEvent(r *http.Request, tok string, trusted bool) types.Event {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	kind := types.EventHTTP
	if r.TLS != nil {
		kind = types.EventHTTPS
	}
	headers := make(map[string]string)
	for k := range r.Header {
		headers[k] = strings.Join(r.Header.Values(k), ", ")
	}
	var body string
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, s.cfg.BodyCaptureLimit))
		body = string(b)
	}
	host := r.Host
	return types.Event{
		Time:        time.Now().UTC(),
		Kind:        kind,
		Token:       tok,
		Trusted:     trusted,
		RemoteAddr:  r.RemoteAddr,
		Scheme:      scheme,
		Method:      r.Method,
		Host:        host,
		Path:        r.URL.RequestURI(),
		Headers:     headers,
		BodyExcerpt: body,
	}
}

func (s *Server) record(ev types.Event, _ types.JobContext, trusted bool) {
	if ev.Token == "" {
		return
	}
	if !trusted {
		ev.Token = "untrusted:" + ev.Token
	}
	s.store.Record(ev)
}

// logging is a minimal access log to stderr-free observability via events;
// panics in handlers are recovered here so one bad request never kills the
// collector.
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = recover() }()
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// SelfSignedTLSConfig mints an ephemeral certificate covering the OOB domain
// (wildcard), apex and, for local drills, loopback addresses.
func SelfSignedTLSConfig(domain string, extraIPs ...net.IP) (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain, "*." + domain},
		IPAddresses:  extraIPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
