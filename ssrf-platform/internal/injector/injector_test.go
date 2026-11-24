package injector

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"ssrf-platform/internal/manifest"
)

func svc() manifest.Service {
	return manifest.Service{
		ID: "preview", BaseURL: "http://preview.internal",
		Headers: map[string]string{"X-Service": "preview"},
		Endpoints: []manifest.Endpoint{{
			ID: "fetch", Path: "/v1/fetch", Method: "POST",
			BodyTemplate: map[string]any{"mode": "async"},
			Params: []manifest.Param{
				{Name: "url", In: "json", JSONPath: "webhook.callback", Placeholder: "https://example.invalid/x"},
				{Name: "timeout", In: "json", JSONPath: "webhook.timeout", Placeholder: "5"},
				{Name: "ref", In: "query", Placeholder: "abc"},
			},
		}},
	}
}

func TestJSONInjectionIsolatesTargetParam(t *testing.T) {
	s := svc()
	ep := s.Endpoints[0]
	target := ep.Params[0]
	req, err := BuildRequest(s, ep, target, "http://oob.example.test/p/PROBE")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("method=%s ct=%s", req.Method, req.Header.Get("Content-Type"))
	}
	raw, _ := io.ReadAll(req.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("body not json: %v (%s)", err, raw)
	}
	wh := body["webhook"].(map[string]any)
	if wh["callback"] != "http://oob.example.test/p/PROBE" {
		t.Fatalf("probe not injected: %v", wh)
	}
	if wh["timeout"] != "5" {
		t.Fatalf("sibling param overwritten: %v", wh)
	}
	if body["mode"] != "async" {
		t.Fatalf("template field lost: %v", body)
	}
	if req.URL.Query().Get("ref") != "abc" {
		t.Fatalf("query placeholder missing: %s", req.URL.RawQuery)
	}
	if req.Header.Get("X-Service") != "preview" {
		t.Fatal("service header not propagated")
	}
}

func TestQueryAndFormInjection(t *testing.T) {
	s := manifest.Service{ID: "s", BaseURL: "http://x", Endpoints: []manifest.Endpoint{{
		ID: "q", Path: "/q", Method: "GET",
		Params: []manifest.Param{
			{Name: "u", In: "query"},
			{Name: "r", In: "query", Placeholder: "z"},
		},
	}}}
	ep := s.Endpoints[0]
	req, err := BuildRequest(s, ep, ep.Params[0], "http://oob/p/T")
	if err != nil {
		t.Fatal(err)
	}
	if q := req.URL.Query(); q.Get("u") != "http://oob/p/T" || q.Get("r") != "z" {
		t.Fatalf("query encoding wrong: %s", req.URL.RawQuery)
	}

	s2 := manifest.Service{ID: "s2", BaseURL: "http://x", Endpoints: []manifest.Endpoint{{
		ID: "f", Path: "/f",
		Params: []manifest.Param{{Name: "u", In: "form"}},
	}}}
	ep2 := s2.Endpoints[0]
	req2, err := BuildRequest(s2, ep2, ep2.Params[0], "http://oob/p/F")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req2.Header.Get("Content-Type"), "form-urlencoded") {
		t.Fatalf("form content type = %q", req2.Header.Get("Content-Type"))
	}
	raw, _ := io.ReadAll(req2.Body)
	if !strings.Contains(string(raw), "u=http%3A%2F%2Foob%2Fp%2FF") {
		t.Fatalf("form body = %q", raw)
	}
}

func TestHeaderInjection(t *testing.T) {
	s := manifest.Service{ID: "s", BaseURL: "http://x", Endpoints: []manifest.Endpoint{{
		ID: "h", Path: "/h",
		Params: []manifest.Param{{Name: "X-Forwarded-Url", In: "header"}},
	}}}
	ep := s.Endpoints[0]
	req, err := BuildRequest(s, ep, ep.Params[0], "http://oob/p/H")
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Forwarded-Url") != "http://oob/p/H" {
		t.Fatalf("header injection = %q", req.Header.Get("X-Forwarded-Url"))
	}
}

func TestAuthFromEnv(t *testing.T) {
	t.Setenv("MY_TOKEN", "secret123")
	s := manifest.Service{
		ID: "s", BaseURL: "http://x", Auth: manifest.Auth{Type: "bearer", Env: "MY_TOKEN"},
		Endpoints: []manifest.Endpoint{{ID: "e", Path: "/", Params: []manifest.Param{{Name: "u", In: "query"}}}},
	}
	ep := s.Endpoints[0]
	req, err := BuildRequest(s, ep, ep.Params[0], "http://oob")
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer secret123" {
		t.Fatalf("auth header = %q", req.Header.Get("Authorization"))
	}
}

var _ http.Header // keep net/http import stable across edits
