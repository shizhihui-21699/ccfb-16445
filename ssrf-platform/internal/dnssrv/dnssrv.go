// Package dns implements the authoritative OOB name server.
//
// Responsibilities:
//   - answer every A/AAAA query for a tokenized name (the resolution itself
//     is the DNS-only SSRF signal) and journal the query as an event;
//   - serve apex NS/SOA so delegations work;
//   - drive per-token rebind plans: the first answer is the public OOB IP,
//     every subsequent answer flips to the internal target, with a 1s TTL so
//     cached answers cannot be relied on.
package dnssrv

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"ssrf-platform/internal/store"
	"ssrf-platform/internal/token"
	"ssrf-platform/internal/types"
)

// RebindPlan is registered per token before a rebind payload is delivered.
type RebindPlan struct {
	Token       string    `json:"token"`
	PublicIP    string    `json:"public_ip"`
	InternalIPs []string  `json:"internal_ips"`
	TTL         uint32    `json:"ttl"`
	CreatedAt   time.Time `json:"created_at"`
	hits        int
}

// Config configures the server.
type Config struct {
	Domain     string // apex domain the server is authoritative for
	ListenUDP  string // e.g. ":53"
	ListenTCP  string
	PublicIP   string // default A answer (the OOB host itself)
	Secret     []byte
	Store      *store.Store
	DataDir    string // where rebind plans are journaled
	DefaultTTL uint32
}

// Server is an authoritative DNS server.
type Server struct {
	cfg Config

	mu    sync.Mutex
	plans map[string]*RebindPlan

	udp *dns.Server
	tcp *dns.Server
}

// New constructs a server and replays persisted rebind plans.
func New(cfg Config) (*Server, error) {
	cfg.Domain = strings.TrimSuffix(strings.ToLower(cfg.Domain), ".") + "."
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 60
	}
	s := &Server{cfg: cfg, plans: make(map[string]*RebindPlan)}
	if err := s.loadPlans(); err != nil {
		return nil, err
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(cfg.Domain, s.handle)
	mux.HandleFunc(".", s.handleRoot)
	s.udp = &dns.Server{Addr: cfg.ListenUDP, Net: "udp", Handler: mux}
	s.tcp = &dns.Server{Addr: cfg.ListenTCP, Net: "tcp", Handler: mux}
	return s, nil
}

// ListenAndServe blocks serving UDP and TCP until Close.
func (s *Server) ListenAndServe() error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()
	err := <-errCh
	_ = s.Close()
	return err
}

// Close stops both listeners.
func (s *Server) Close() error {
	var first error
	if s.udp != nil {
		first = s.udp.Shutdown()
	}
	if s.tcp != nil {
		if err := s.tcp.Shutdown(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// RegisterPlan stores a rebind plan and journals it.
func (s *Server) RegisterPlan(p RebindPlan) error {
	if net.ParseIP(p.PublicIP) == nil {
		return fmt.Errorf("dns: bad public ip %q", p.PublicIP)
	}
	for _, ip := range p.InternalIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("dns: bad internal ip %q", ip)
		}
	}
	if p.TTL == 0 {
		p.TTL = 1
	}
	p.CreatedAt = time.Now().UTC()
	s.mu.Lock()
	stored := p
	s.plans[p.Token] = &stored
	s.mu.Unlock()
	// Marshal the immutable registration fields outside the lock; hits is a
	// runtime counter excluded from the snapshot.
	return s.persistPlan(RebindPlan{
		Token: p.Token, PublicIP: p.PublicIP, InternalIPs: p.InternalIPs,
		TTL: p.TTL, CreatedAt: p.CreatedAt,
	})
}

func (s *Server) planPath() string { return filepath.Join(s.cfg.DataDir, "rebind.jsonl") }

func (s *Server) persistPlan(p RebindPlan) error {
	if s.cfg.DataDir == "" {
		return nil
	}
	if err := os.MkdirAll(s.cfg.DataDir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.planPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(p)
	_, err = f.Write(append(line, '\n'))
	return err
}

func (s *Server) loadPlans() error {
	if s.cfg.DataDir == "" {
		return nil
	}
	f, err := os.Open(s.planPath())
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var p RebindPlan
		if json.Unmarshal(sc.Bytes(), &p) == nil && p.Token != "" {
			s.plans[p.Token] = &p
		}
	}
	return sc.Err()
}

// answerFor implements the rebind state machine for one token.
func (s *Server) answerFor(tok string) (ips []string, ttl uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[tok]
	if !ok {
		return []string{s.cfg.PublicIP}, s.cfg.DefaultTTL
	}
	p.hits++
	if p.hits <= 1 {
		return []string{p.PublicIP}, p.TTL
	}
	return p.InternalIPs, p.TTL
}

func (s *Server) handleRoot(w dns.ResponseWriter, r *dns.Msg) {
	// Refuse everything outside the delegated zone rather than acting as an
	// open resolver.
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	_ = w.WriteMsg(m)
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Apex service records.
	if name == s.cfg.Domain {
		s.serveApex(r, m, q)
		_ = w.WriteMsg(m)
		return
	}

	flat, ctx, trusted := token.Extract(name, s.cfg.Domain, s.cfg.Secret)
	qtype := dns.TypeToString[q.Qtype]

	switch q.Qtype {
	case dns.TypeA:
		ips, ttl := s.answerFor(flat)
		for _, ip := range ips {
			if v4 := net.ParseIP(ip).To4(); v4 != nil {
				rr := &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: v4}
				m.Answer = append(m.Answer, rr)
			}
		}
		s.logDNS(flat, ctx, trusted, name, qtype, ips, w.RemoteAddr())
	case dns.TypeAAAA:
		// Empty NOERROR answer: force IPv4 fallback and still record the look-up.
		s.logDNS(flat, ctx, trusted, name, qtype, nil, w.RemoteAddr())
	default:
		// TXT/CNAME/etc.: no answer, but keep the interaction trail.
		s.logDNS(flat, ctx, trusted, name, qtype, nil, w.RemoteAddr())
	}
	_ = w.WriteMsg(m)
}

func (s *Server) serveApex(r, m *dns.Msg, q dns.Question) {
	ns := "ns1." + s.cfg.Domain
	switch q.Qtype {
	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: s.cfg.DefaultTTL}, Ns: ns})
	case dns.TypeSOA:
		m.Answer = append(m.Answer, &dns.SOA{
			Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.cfg.DefaultTTL},
			Ns:      ns,
			Mbox:    "hostmaster." + s.cfg.Domain,
			Serial:  uint32(time.Now().Unix()),
			Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 60,
		})
	case dns.TypeA:
		if v4 := net.ParseIP(s.cfg.PublicIP).To4(); v4 != nil {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.cfg.DefaultTTL}, A: v4})
		}
	}
}

func (s *Server) logDNS(flat string, ctx types.JobContext, trusted bool, name, qtype string, answers []string, remote net.Addr) {
	if flat == "" {
		return
	}
	tok := flat
	if !trusted {
		tok = "untrusted:" + flat
	}
	ev := types.Event{
		Time:       time.Now().UTC(),
		Kind:       types.EventDNS,
		Token:      tok,
		Trusted:    trusted,
		RemoteAddr: remote.String(),
		DNSName:    name,
		DNSQType:   qtype,
		DNSAnswers: append([]string(nil), answers...),
	}
	if trusted {
		ev.Host = name
	}
	s.cfg.Store.Record(ev)
}
