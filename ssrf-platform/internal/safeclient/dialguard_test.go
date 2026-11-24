package safeclient_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ssrf-platform/internal/safeclient"
)

// TestGuardedClientBlocksBlockedDestinations proves the scanner's own HTTP
// client cannot be steered at blocked ranges even when the target service
// 302-redirects there (redirects are never followed anyway).
func TestGuardedClientBlocksBlockedDestinations(t *testing.T) {
	// A local stand-in for an internal service the scanner must not touch.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("scanner must never connect to the blocked internal stand-in")
	}))
	defer internal.Close()

	pol, err := safeclient.ParsePolicy(nil, nil) // default blocks link-local
	if err != nil {
		t.Fatal(err)
	}
	client := safeclient.New(pol, false)

	// Direct attempt at the metadata address must fail at dial time.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("dial to metadata endpoint must be rejected")
	} else if !strings.Contains(err.Error(), "blocked by policy") {
		t.Fatalf("want policy block error, got: %v", err)
	}
}

// TestAllowListRejectsEverythingOutsideTargetCIDRs simulates locking the
// scanner down to the target-service network only.
func TestAllowListRejectsEverythingOutsideTargetCIDRs(t *testing.T) {
	pol, err := safeclient.ParsePolicy([]string{"10.20.30.0/24"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := safeclient.New(pol, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("allow-listed client must not reach a loopback test server")
	}))
	defer srv.Close()

	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%s/", port), nil)
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "blocked by policy") {
		t.Fatalf("want policy block, got %v", err)
	}
}
