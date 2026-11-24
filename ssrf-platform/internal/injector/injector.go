// Package injector turns a manifest endpoint plus one probe value into a
// concrete *http.Request. All other parameters on the endpoint are filled
// with benign placeholders so only the parameter under test carries the
// probe — this is what makes per-parameter attribution possible.
package injector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"ssrf-platform/internal/manifest"
)

// BuildRequest constructs the request for targetParam=probeValue.
func BuildRequest(svc manifest.Service, ep manifest.Endpoint, target manifest.Param, probeValue string) (*http.Request, error) {
	u, err := url.Parse(strings.TrimRight(svc.BaseURL, "/") + ep.Path)
	if err != nil {
		return nil, fmt.Errorf("injector: bad url: %w", err)
	}

	query := url.Values{}
	form := url.Values{}
	jsonBody := cloneTemplate(ep.BodyTemplate)
	headerVals := map[string]string{}
	bodyKind := bodyKindOf(ep)

	for _, p := range ep.Params {
		val := p.Placeholder
		if p.Name == target.Name && p.In == target.In {
			val = probeValue
		}
		if val == "" {
			val = benignValue(p)
		}
		switch p.In {
		case "query":
			query.Set(p.Name, val)
		case "form":
			form.Set(p.Name, val)
		case "header":
			headerVals[p.Name] = val
		case "json":
			setNested(jsonBody, p.JSONPath, val)
		}
	}

	method := ep.Method
	var body io.Reader
	contentType := ""
	switch {
	case bodyKind == "json" || len(jsonBody) > 0:
		raw, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, fmt.Errorf("injector: json body: %w", err)
		}
		body = bytes.NewReader(raw)
		contentType = "application/json"
	case len(form) > 0:
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	if method == "GET" && body != nil {
		method = "POST"
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range svc.Headers {
		req.Header.Set(k, v)
	}
	if len(query) > 0 {
		req.URL.RawQuery = query.Encode()
	}
	for k, v := range headerVals {
		req.Header.Set(k, v)
	}
	applyAuth(req, svc.Auth)
	return req, nil
}

func bodyKindOf(ep manifest.Endpoint) string {
	for _, p := range ep.Params {
		if p.In == "form" {
			return "form"
		}
	}
	return "json"
}

func cloneTemplate(t map[string]any) map[string]any {
	if t == nil {
		return map[string]any{}
	}
	raw, _ := json.Marshal(t)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

// setNested writes value at dotted path, creating intermediate objects.
func setNested(root map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	cur := root
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}

func benignValue(p manifest.Param) string {
	switch p.In {
	case "query", "form", "json":
		return "https://example.invalid/benign"
	default:
		return "benign-value"
	}
}

func applyAuth(req *http.Request, a manifest.Auth) {
	secret := os.Getenv(a.Env)
	switch a.Type {
	case "bearer":
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
	case "header":
		if a.Header != "" && secret != "" {
			req.Header.Set(a.Header, secret)
		}
	}
}
