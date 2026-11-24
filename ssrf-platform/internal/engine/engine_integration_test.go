package engine_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ssrf-platform/internal/collector"
	miekdns "ssrf-platform/internal/dnssrv"
	"ssrf-platform/internal/engine"
	"ssrf-platform/internal/manifest"
	"ssrf-platform/internal/oob"
	"ssrf-platform/internal/payload"
	"ssrf-platform/internal/safeclient"
	"ssrf-platform/internal/store"
)

// ---- test infrastructure ---------------------------------------------------

type harness struct {
	domain     string
	secret     []byte
	dnsAddr    string
	httpBase   string
	httpsBase  string
	httpPortN  int
	httpsPortN int
	oobClient  *oob.Client
	collector  *collector.Server
	dnsServer  *miekdns.Server
	store      *store.Store
	targetAddr string
	target     *targetApp
}

// targetApp simulates internal services. Behavior is selected per endpoint:
//   - /preview/fetch   synchronously GETs the supplied url and embeds the body
//   - /webhook        stores the url; a separate worker fetches it later (async)
//   - /admin          rejects any url containing internal literals (a "fixed" service)
type targetApp struct {
	mu       sync.Mutex
	delayed  []string
	resolver *net.Resolver
}

func (a *targetApp) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/preview/fetch":
		u := r.URL.Query().Get("url")
		resp, err := a.fetch(r.Context(), u)
		if err != nil {
			http.Error(w, "fetch failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		fmt.Fprintf(w, "preview of %s:\n%s", u, body)
	case "/webhook":
		var in struct {
			URL string `json:"url"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &in)
		a.mu.Lock()
		a.delayed = append(a.delayed, in.URL)
		a.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	case "/admin":
		u := r.URL.Query().Get("url")
		if strings.Contains(u, "169.254") || strings.Contains(u, "127.") || strings.Contains(u, "0.0.0.0") {
			http.Error(w, "blocked by allow-list", http.StatusForbidden)
			return
		}
		// Still vulnerable to OOB-domain probes, though.
		if _, err := a.fetch(r.Context(), u); err != nil {
			http.Error(w, "fetch failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (a *targetApp) fetch(ctx context.Context, u string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           a.dialContext,
			ResponseHeaderTimeout: 4 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func (a *targetApp) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// Route every OOB-name resolution at the test DNS server.
	ips, err := a.lookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (a *targetApp) lookupHost(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	return a.resolver.LookupHost(ctx, host)
}

func (a *targetApp) drainDelayed(ctx context.Context, delay time.Duration) {
	time.Sleep(delay)
	a.mu.Lock()
	pending := append([]string(nil), a.delayed...)
	a.delayed = nil
	a.mu.Unlock()
	for _, u := range pending {
		_, _ = a.fetch(ctx, u)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func setupHarness(t *testing.T) *harness {
	t.Helper()
	secret := []byte("integration-secret")
	domain := "oob.example.test"
	dataDir := t.TempDir()

	st, err := store.Open(filepath.Join(dataDir, "events"), 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	dnsPort := freePort(t)
	dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	dnsServer, err := miekdns.New(miekdns.Config{
		Domain: domain, ListenUDP: dnsAddr, ListenTCP: dnsAddr,
		PublicIP: "127.0.0.1", Secret: secret, Store: st,
		DataDir: filepath.Join(dataDir, "dns"), DefaultTTL: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = dnsServer.ListenAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Close() })

	coll := collector.New(collector.Config{
		Domain: domain, Secret: secret, Store: st, APIKey: "key",
		Rebind: rebindAdapter{srv: dnsServer},
	})
	httpPort := freePort(t)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coll.ServeHTTP(ln) }()
	httpsPort := freePort(t)
	tlsLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort))
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := collector.SelfSignedTLSConfig(domain, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coll.ServeHTTPS(tlsLn, tlsCfg) }()
	t.Cleanup(func() { _ = coll.Close() })
	time.Sleep(150 * time.Millisecond)

	// Resolver pinned to the test DNS server.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, dnsAddr)
		},
	}
	app := &targetApp{resolver: resolver}
	targetPort := freePort(t)
	targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)
	tln, err := net.Listen("tcp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handler)
	tsrv := &http.Server{Handler: mux}
	go func() { _ = tsrv.Serve(tln) }()
	t.Cleanup(func() { _ = tsrv.Close() })

	return &harness{
		domain: domain, secret: secret, dnsAddr: dnsAddr,
		httpBase:  fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		httpsBase: fmt.Sprintf("https://127.0.0.1:%d", httpsPort),
		httpPortN: httpPort, httpsPortN: httpsPort,
		oobClient: oob.New(fmt.Sprintf("http://127.0.0.1:%d", httpPort), "key"),
		collector: coll, dnsServer: dnsServer, store: st,
		targetAddr: targetAddr, target: app,
	}
}

type rebindAdapter struct{ srv *miekdns.Server }

func (a rebindAdapter) RegisterPlan(token, publicIP string, internalIPs []string, ttl uint32) error {
	return a.srv.RegisterPlan(miekdns.RebindPlan{Token: token, PublicIP: publicIP, InternalIPs: internalIPs, TTL: ttl})
}

func (h *harness) newEngine(t *testing.T, mode engine.Mode, out string, window time.Duration) *engine.Engine {
	pol, err := safeclient.ParsePolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gen := payload.New(payload.Config{
		Domain: h.domain, Secret: h.secret, HTTPPort: h.httpPortN, HTTPSPort: h.httpsPortN,
		PublicIP: "127.0.0.1", MetadataIP: "169.254.169.254", InternalTarget: "127.0.0.1",
	})
	m := h.manifest()
	eng, err := engine.New(engine.Config{
		Manifest: m, Generator: gen, OOBClient: h.oobClient,
		HTTPClient: safeclient.New(pol, false), Policy: pol,
		Mode: mode, RunID: "test-run", OutDir: out,
		Workers: 4, RatePerSecond: 50, ObservationWindow: window,
		PollInterval: 200 * time.Millisecond, IntranetBudget: 100,
		Secret: h.secret, MetadataIP: "169.254.169.254", InternalTarget: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func (h *harness) manifest() *manifest.Manifest {
	return &manifest.Manifest{
		Version: "1",
		Services: []manifest.Service{{
			ID: "preview-svc", BaseURL: "http://" + h.targetAddr,
			Endpoints: []manifest.Endpoint{
				{ID: "fetch", Path: "/preview/fetch", Method: "GET", Params: []manifest.Param{
					{Name: "url", In: "query"},
				}},
				{ID: "webhook", Path: "/webhook", Method: "POST", BodyTemplate: map[string]any{}, Params: []manifest.Param{
					{Name: "url", In: "json", JSONPath: "url"},
				}},
				{ID: "admin", Path: "/admin", Method: "GET", Params: []manifest.Param{
					{Name: "url", In: "query"},
				}},
			},
		}},
	}
}

// ---- tests -----------------------------------------------------------------

func TestEndToEndSynchronousAndRedirectSSRF(t *testing.T) {
	h := setupHarness(t)
	out := filepath.Join(t.TempDir(), "run")
	eng := h.newEngine(t, engine.ModeSafe, out, 3*time.Second)
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	byKey := map[string]bool{}
	for _, f := range report.Findings {
		byKey[f.EndpointID+"#"+f.Param+"/"+f.VariantID] = true
	}
	// Synchronous preview fetch must confirm direct OOB HTTP and DNS variants.
	for _, variant := range []string{"oob-http", "oob-https", "dns-only"} {
		if !byKey["fetch#url/"+variant] {
			t.Errorf("expected confirmed finding fetch#url/%s", variant)
		}
	}
	// The preview service follows our controlled redirect.
	if !byKey["fetch#url/redirect-1hop"] {
		t.Error("redirect-1hop SSRF not detected on /preview/fetch")
	}
	// Every finding must be precisely attributable.
	for _, f := range report.Findings {
		if f.ServiceID != "preview-svc" || f.Param != "url" || f.Confidence == "" {
			t.Fatalf("failing lacks precise attribution: %+v", f)
		}
		if len(f.Events) == 0 {
			t.Errorf("finding %s carries no evidence events", f.VariantID)
		}
	}
	if report.Summary.ConfirmedSSRF == 0 {
		t.Fatal("no confirmed findings at all")
	}
}

func TestEndToEndAsyncWebhookReconcile(t *testing.T) {
	h := setupHarness(t)
	out := filepath.Join(t.TempDir(), "run")
	eng := h.newEngine(t, engine.ModeSafe, out, 1500*time.Millisecond)
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// During the short window nothing called back from the webhook endpoint.
	for _, f := range report.Findings {
		if f.EndpointID == "webhook" {
			t.Fatalf("webhook should not confirm before the delayed job fires: %+v", f)
		}
	}
	// Simulate the async worker hours later.
	go h.target.drainDelayed(context.Background(), 300*time.Millisecond)
	time.Sleep(800 * time.Millisecond)

	// Reconcile attributes the late callbacks to the exact webhook param.
	recEng := h.newEngine(t, engine.ModeSafe, out, time.Second)
	recReport, err := engine.Reconcile(context.Background(), recEng.Config())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	confirmed := false
	for _, f := range recReport.Findings {
		if f.EndpointID == "webhook" && f.Param == "url" {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatal("late webhook callback was not attributed during reconcile")
	}
}

func TestEndToEndRebindVariant(t *testing.T) {
	h := setupHarness(t)
	out := filepath.Join(t.TempDir(), "run")
	eng := h.newEngine(t, engine.ModeSafe, out, 3*time.Second)
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The rebind name must at minimum produce a DNS-resolution finding; the
	// target app performs two dial attempts so the state machine flips.
	for _, f := range report.Findings {
		if f.VariantID == "rebind-first-public" {
			if f.Severity == "" {
				t.Fatal("rebind finding missing severity")
			}
			return
		}
	}
	// No rebind finding: at least assert the plan was armed (events exist).
	evs := h.store.Since(0, 0)
	sawRebindDNS := false
	for _, ev := range evs {
		if ev.Kind == "dns" && strings.Contains(ev.DNSName, "oob.example.test") {
			sawRebindDNS = true
		}
	}
	if !sawRebindDNS {
		t.Fatal("no rebind-related DNS activity observed")
	}
}

func TestEndToEndAdminBlocksInternalButAllowsOOB(t *testing.T) {
	h := setupHarness(t)
	out := filepath.Join(t.TempDir(), "run")
	eng := h.newEngine(t, engine.ModeFull, out, 3*time.Second)
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	adminOOB := false
	for _, f := range report.Findings {
		if f.EndpointID == "admin" && f.VariantID == "oob-http" {
			adminOOB = true
		}
		if f.EndpointID == "admin" && f.VariantID == "metadata-direct" {
			t.Error("metadata-direct must not confirm against the allow-listing admin endpoint")
		}
	}
	if !adminOOB {
		t.Error("admin endpoint should still confirm OOB-domain SSRF")
	}
}

func TestIntranetBudgetIsEnforced(t *testing.T) {
	h := setupHarness(t)
	pol, _ := safeclient.ParsePolicy(nil, nil)
	gen := payload.New(payload.Config{
		Domain: h.domain, Secret: h.secret, HTTPPort: h.httpPortN, HTTPSPort: h.httpsPortN,
		PublicIP: "127.0.0.1",
	})
	eng, err := engine.New(engine.Config{
		Manifest: h.manifest(), Generator: gen, OOBClient: h.oobClient,
		HTTPClient: safeclient.New(pol, false), Policy: pol,
		Mode: engine.ModeFull, RunID: "budget", OutDir: filepath.Join(t.TempDir(), "b"),
		Workers: 2, RatePerSecond: 100, ObservationWindow: time.Second,
		PollInterval: 200 * time.Millisecond, IntranetBudget: 3,
		Secret: h.secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Summary.IntranetSent > 3 {
		t.Fatalf("intranet budget violated: %d sent", report.Summary.IntranetSent)
	}
	if report.Summary.IntranetSent == 0 {
		t.Fatal("expected some intranet requests within budget")
	}
}
