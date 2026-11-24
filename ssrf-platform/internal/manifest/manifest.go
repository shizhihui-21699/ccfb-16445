// Package manifest defines the declarative scan targets. One manifest
// describes hundreds of services; each injectable parameter is listed
// explicitly so findings can name the exact service / endpoint / parameter.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
)

// Manifest is the top-level scan description.
type Manifest struct {
	Version  string    `json:"version"`
	Services []Service `json:"services"`
}

// Auth describes how requests to one service are authenticated.
type Auth struct {
	// Type is "none", "bearer" or "header".
	Type   string `json:"type"`
	Header string `json:"header,omitempty"` // for "header"
	// Env names the environment variable holding the secret value; secrets
	// never live in the manifest itself.
	Env string `json:"env,omitempty"`
}

// Service groups endpoints sharing a base URL.
type Service struct {
	ID          string            `json:"id"`
	BaseURL     string            `json:"base_url"`
	Description string            `json:"description,omitempty"`
	Auth        Auth              `json:"auth,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	// SkipTLSVerify allows self-signed certificates in test environments.
	SkipTLSVerify bool       `json:"skip_tls_verify,omitempty"`
	Endpoints     []Endpoint `json:"endpoints"`
}

// Endpoint is one HTTP route.
type Endpoint struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Method string `json:"method,omitempty"` // default GET
	// BodyTemplate is an optional JSON object merged with JSON-injected params.
	BodyTemplate map[string]any `json:"body_template,omitempty"`
	Params       []Param        `json:"params"`
}

// Param is one injectable input.
type Param struct {
	Name string `json:"name"`
	// In is one of query, json, form, header.
	In string `json:"in"`
	// JSONPath locates the field inside a JSON body, e.g. "webhook.callback".
	JSONPath string `json:"json_path,omitempty"`
	// Placeholder is the benign value used for the other params in the same
	// request while this one carries the probe.
	Placeholder string `json:"placeholder,omitempty"`
}

// Load reads and validates a manifest file.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: parse: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks structural invariants and fills defaults.
func (m *Manifest) Validate() error {
	if len(m.Services) == 0 {
		return fmt.Errorf("manifest: no services defined")
	}
	seenServices := map[string]bool{}
	for si := range m.Services {
		svc := &m.Services[si]
		if svc.ID == "" {
			return fmt.Errorf("manifest: service #%d missing id", si)
		}
		if seenServices[svc.ID] {
			return fmt.Errorf("manifest: duplicate service id %q", svc.ID)
		}
		seenServices[svc.ID] = true
		if svc.BaseURL == "" {
			return fmt.Errorf("manifest: service %q missing base_url", svc.ID)
		}
		if svc.Auth.Type == "" {
			svc.Auth.Type = "none"
		}
		switch svc.Auth.Type {
		case "none", "bearer", "header":
		default:
			return fmt.Errorf("manifest: service %q unknown auth type %q", svc.ID, svc.Auth.Type)
		}
		if len(svc.Endpoints) == 0 {
			return fmt.Errorf("manifest: service %q has no endpoints", svc.ID)
		}
		seenEP := map[string]bool{}
		for ei := range svc.Endpoints {
			ep := &svc.Endpoints[ei]
			if ep.ID == "" {
				return fmt.Errorf("manifest: service %q endpoint #%d missing id", svc.ID, ei)
			}
			key := svc.ID + "/" + ep.ID
			if seenEP[key] {
				return fmt.Errorf("manifest: duplicate endpoint id %q", key)
			}
			seenEP[key] = true
			if ep.Method == "" {
				ep.Method = "GET"
			}
			if len(ep.Params) == 0 {
				return fmt.Errorf("manifest: endpoint %q has no params", key)
			}
			for _, p := range ep.Params {
				switch p.In {
				case "query", "json", "form", "header":
				default:
					return fmt.Errorf("manifest: param %q on %q has unknown location %q", p.Name, key, p.In)
				}
				if p.In == "json" && p.JSONPath == "" {
					return fmt.Errorf("manifest: json param %q on %q missing json_path", p.Name, key)
				}
			}
		}
	}
	return nil
}
