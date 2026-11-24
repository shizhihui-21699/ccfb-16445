package collector

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"ssrf-platform/internal/store"
	"ssrf-platform/internal/token"
	"ssrf-platform/internal/types"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func startCollector(t *testing.T, allowIntranet bool, registrar RebindRegistrar) (*Server, string, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "st"), 16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv := New(Config{
		Domain: "oob.example.test", Secret: []byte("k"), Store: st,
		APIKey: "key", AllowIntranetRedirects: allowIntranet, Rebind: registrar,
	})
	addr := freePort(t)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.http.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	time.Sleep(100 * time.Millisecond)
	return srv, "http://" + addr, st
}

func tokenFor(variant string) (string, string) {
	c := types.JobContext{Version: 1, TaskID: 3, RunID: "r", ServiceID: "s", EndpointID: "e", Param: "p", VariantID: variant}
	return token.Encode(c, []byte("k")), c.VariantID
}

func TestMarkerPageAndEventLookup(t *testing.T) {
	_, base, st := startCollector(t, false, nil)
	tok, _ := tokenFor("oob-http")
	resp, err := http.Get(base + "/p/" + tok)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(markerPrefix+tok)) {
		t.Fatalf("marker response wrong: %d %s", resp.StatusCode, body)
	}
	evs, err := st.Lookup(tok)
	if err != nil || len(evs) != 1 || evs[0].Kind != types.EventHTTP || !evs[0].Trusted {
		t.Fatalf("event not recorded correctly: %v %+v", err, evs)
	}

	// API requires the key.
	req, _ := http.NewRequest(http.MethodGet, base+"/api/events?token="+tok, nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API call: %d", resp2.StatusCode)
	}
	req.Header.Set("X-API-Key", "key")
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got []types.Event
	_ = json.NewDecoder(resp3.Body).Decode(&got)
	resp3.Body.Close()
	if len(got) != 1 {
		t.Fatalf("api returned %d events", len(got))
	}
}

func TestRedirectChainStaysInsideDomainByDefault(t *testing.T) {
	_, base, _ := startCollector(t, false, nil)
	tok, _ := tokenFor("redirect-3hop")
	client := &http.Client{Timeout: 5 * time.Second} // follows redirects, unlike the scanner
	resp, err := client.Get(base + "/r/" + tok + "?hops=2")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte(markerPrefix+tok)) {
		t.Fatalf("chain did not terminate on marker page: %s", body)
	}
}

func TestExternalRedirectGatedByPolicy(t *testing.T) {
	_, base, _ := startCollector(t, false, nil)
	tok, _ := tokenFor("redirect-to-metadata")
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	target := "http://169.254.169.254/"
	resp, err := client.Get(base + "/r/" + tok + "?hops=0&to=" + target)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Policy off: the final hop is ignored and the marker page is served.
	if resp.StatusCode != 200 {
		t.Fatalf("external redirect must be suppressed, got %d", resp.StatusCode)
	}
}

type fakeRegistrar struct{ calls int }

func (f *fakeRegistrar) RegisterPlan(token, publicIP string, internalIPs []string, ttl uint32) error {
	f.calls++
	return nil
}

func TestRebindAPI(t *testing.T) {
	reg := &fakeRegistrar{}
	_, base, _ := startCollector(t, false, reg)
	payload := map[string]any{"token": "t", "public_ip": "1.1.1.1", "internal_ips": []string{"127.0.0.1"}, "ttl": 1}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, base+"/api/rebind", bytes.NewReader(raw))
	req.Header.Set("X-API-Key", "key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || reg.calls != 1 {
		t.Fatalf("rebind arm failed: status=%d calls=%d", resp.StatusCode, reg.calls)
	}
}
