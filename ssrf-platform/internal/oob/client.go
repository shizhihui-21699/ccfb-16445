// Package oob is the scanner-side client for the OOB collector's API.
package oob

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"ssrf-platform/internal/types"
)

// Client talks to one OOB collector.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// New builds a client with sensible timeouts.
func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("oob: %s %s -> %d %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
	}
	return nil
}

// Events returns all events recorded for one flat token.
func (c *Client) Events(ctx context.Context, token string) ([]types.Event, error) {
	var out []types.Event
	err := c.do(ctx, http.MethodGet, "/api/events?token="+url.QueryEscape(token), nil, &out)
	return out, err
}

// Since returns events newer than seq.
func (c *Client) Since(ctx context.Context, seq uint64, limit int) ([]types.Event, error) {
	path := fmt.Sprintf("/api/events/since?seq=%d&limit=%d", seq, limit)
	var out []types.Event
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// RebindPlan arms a DNS rebind plan.
type RebindPlan struct {
	Token       string   `json:"token"`
	PublicIP    string   `json:"public_ip"`
	InternalIPs []string `json:"internal_ips"`
	TTL         uint32   `json:"ttl"`
}

// ArmRebind registers a rebind plan through the collector API.
func (c *Client) ArmRebind(ctx context.Context, p RebindPlan) error {
	return c.do(ctx, http.MethodPost, "/api/rebind", p, nil)
}
