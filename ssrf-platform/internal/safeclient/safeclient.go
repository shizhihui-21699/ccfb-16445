// Package safeclient builds the HTTP client the scanner uses to deliver
// probes to target services.
//
// Two guardrails make scanning non-destructive:
//
//  1. Redirects are never followed. A vulnerable service's redirect chain is
//     observed through the OOB collector instead, which keeps the scanner
//     itself from being bounced into internal hosts.
//  2. A dial-time Control hook validates every resolved IP against the
//     policy. The default policy hard-blocks link-local ranges (including the
//     cloud metadata endpoint); an optional allow-list restricts outbound
//     traffic to the target-service CIDRs.
package safeclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Policy controls which destination IPs the scanner may dial.
type Policy struct {
	// AllowCIDRs switches to allow-list mode: only these ranges are dialable.
	AllowCIDRs []*net.IPNet
	// BlockCIDRs always applies, even on top of an allow-list.
	BlockCIDRs []*net.IPNet
}

// defaultBlockRanges always blocks link-local and metadata destinations.
var defaultBlockRanges = []string{
	"169.254.0.0/16", // IPv4 link-local, incl. 169.254.169.254
	"fe80::/10",      // IPv6 link-local
	"224.0.0.0/4",    // multicast
	"ff00::/8",
}

// ParsePolicy compiles CIDR strings. Empty allowCIDRs means "allow all except
// the block list". The metadata / link-local block is always appended.
func ParsePolicy(allowCIDRs, blockCIDRs []string) (*Policy, error) {
	p := &Policy{}
	for _, c := range append(append([]string{}, defaultBlockRanges...), blockCIDRs...) {
		n, err := parseCIDR(c)
		if err != nil {
			return nil, err
		}
		p.BlockCIDRs = append(p.BlockCIDRs, n)
	}
	for _, c := range allowCIDRs {
		n, err := parseCIDR(c)
		if err != nil {
			return nil, err
		}
		p.AllowCIDRs = append(p.AllowCIDRs, n)
	}
	return p, nil
}

func parseCIDR(c string) (*net.IPNet, error) {
	if !strings.Contains(c, "/") {
		ip := net.ParseIP(c)
		if ip == nil {
			return nil, fmt.Errorf("safeclient: bad cidr %q", c)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		return nil, fmt.Errorf("safeclient: bad cidr %q: %w", c, err)
	}
	return n, nil
}

// Allowed reports whether dialing ip is permitted.
func (p *Policy) Allowed(ip net.IP) bool {
	for _, n := range p.BlockCIDRs {
		if n.Contains(ip) {
			return false
		}
	}
	if len(p.AllowCIDRs) == 0 {
		return true
	}
	for _, n := range p.AllowCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// New returns a guarded client. skipTLSVerify is for lab environments only.
func New(p *Policy, skipTLSVerify bool) *http.Client {
	d := &guardDialer{
		Dialer: &net.Dialer{Timeout: 10 * time.Second},
		policy: p,
	}
	tr := &http.Transport{
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipTLSVerify, MinVersion: tls.VersionTLS12},
		DisableKeepAlives:     true,
		MaxIdleConns:          -1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type guardDialer struct {
	*net.Dialer
	policy *Policy
}

func (g *guardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ia := range ips {
		if !g.policy.Allowed(ia.IP) {
			lastErr = fmt.Errorf("safeclient: destination %s (%s) blocked by policy", host, ia.IP)
			continue
		}
		conn, err := g.Dialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), portOnly(addr)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("safeclient: no allowed address for %s", host)
	}
	return nil, lastErr
}

func portOnly(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "80"
	}
	return port
}
