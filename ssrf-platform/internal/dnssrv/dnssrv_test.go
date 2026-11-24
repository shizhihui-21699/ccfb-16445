package dnssrv

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"ssrf-platform/internal/store"
	"ssrf-platform/internal/token"
	"ssrf-platform/internal/types"
)

func freeUDPPort(t *testing.T) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	_ = l.Close()
	return addr
}

func newTestServer(t *testing.T, secret []byte) (*Server, string) {
	t.Helper()
	addr := freeUDPPort(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "st"), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv, err := New(Config{
		Domain: "oob.example.test", ListenUDP: addr, ListenTCP: addr,
		PublicIP: "203.0.113.10", Secret: secret, Store: st,
		DataDir: filepath.Join(t.TempDir(), "dns"), DefaultTTL: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Close() })
	time.Sleep(100 * time.Millisecond)
	return srv, addr
}

func queryA(t *testing.T, server, name string) *dns.Msg {
	t.Helper()
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatalf("dns exchange %s: %v", name, err)
	}
	return resp
}

func TestTokenizedNameResolvesAndJournals(t *testing.T) {
	secret := []byte("k")
	srv, addr := newTestServer(t, secret)
	c := types.JobContext{Version: 1, TaskID: 1, RunID: "r", ServiceID: "s", EndpointID: "e", Param: "p", VariantID: "dns-only"}
	name := token.DNSName(c, "oob.example.test", secret)
	resp := queryA(t, addr, name)
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 A record, got %d", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if a.A.String() != "203.0.113.10" || a.Hdr.Ttl != 30 {
		t.Fatalf("unexpected answer %+v", a)
	}
	flat, _, trusted := token.Extract(name, "oob.example.test", secret)
	if !trusted {
		t.Fatal("token not trusted")
	}
	evs, err := srv.cfg.Store.Lookup(flat)
	if err != nil {
		t.Fatalf("dns event not journaled: %v", err)
	}
	if evs[0].Kind != types.EventDNS || evs[0].DNSQType != "A" {
		t.Fatalf("wrong event: %+v", evs[0])
	}
}

func TestRebindStateMachineFlipsAfterFirstHit(t *testing.T) {
	secret := []byte("k")
	srv, addr := newTestServer(t, secret)
	c := types.JobContext{Version: 1, TaskID: 9, RunID: "r", ServiceID: "s", EndpointID: "e", Param: "p", VariantID: "rebind-first-public"}
	name := token.DNSName(c, "oob.example.test", secret)
	flat, _, _ := token.Extract(name, "oob.example.test", secret)
	if err := srv.RegisterPlan(RebindPlan{
		Token: flat, PublicIP: "203.0.113.10", InternalIPs: []string{"127.0.0.2"}, TTL: 1,
	}); err != nil {
		t.Fatal(err)
	}
	first := queryA(t, addr, name)
	second := queryA(t, addr, name)
	third := queryA(t, addr, name)
	got := func(m *dns.Msg) string {
		if len(m.Answer) == 0 {
			return ""
		}
		return m.Answer[0].(*dns.A).A.String()
	}
	if got(first) != "203.0.113.10" {
		t.Fatalf("first answer must be public IP, got %q", got(first))
	}
	if first.Answer[0].(*dns.A).Hdr.Ttl != 1 {
		t.Fatal("rebind answers must use the short TTL")
	}
	if got(second) != "127.0.0.2" || got(third) != "127.0.0.2" {
		t.Fatalf("subsequent answers must stay internal, got %q %q", got(second), got(third))
	}
}

func TestApexRecordsAndOutsideZoneRefusal(t *testing.T) {
	_, addr := newTestServer(t, []byte("k"))
	soa := queryA(t, addr, "oob.example.test.")
	if soa.Rcode != dns.RcodeSuccess || len(soa.Answer) != 1 {
		t.Fatalf("apex query: rcode=%d answers=%d", soa.Rcode, len(soa.Answer))
	}
	other := queryA(t, addr, "evil.example.net.")
	if other.Rcode != dns.RcodeRefused {
		t.Fatalf("out-of-zone query rcode = %d, want REFUSED", other.Rcode)
	}
}

func TestPlanPersistenceRejectsBadIPs(t *testing.T) {
	srv, _ := newTestServer(t, []byte("k"))
	if err := srv.RegisterPlan(RebindPlan{Token: "x", PublicIP: "nope", InternalIPs: []string{"127.0.0.1"}}); err == nil {
		t.Fatal("bad public IP must error")
	}
	if err := srv.RegisterPlan(RebindPlan{Token: "x", PublicIP: "1.1.1.1", InternalIPs: []string{"bad"}}); err == nil {
		t.Fatal("bad internal IP must error")
	}
	if !strings.HasSuffix(srv.planPath(), "rebind.jsonl") {
		t.Fatal("unexpected plan journal path")
	}
}
