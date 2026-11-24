// Package types defines the domain objects shared by the scanner, the OOB
// server and the correlation engine.
package types

import "time"

// VariantClass groups payload variants by their intranet impact.
type VariantClass string

const (
	// ClassOOB only ever contacts the attacker-controlled OOB infrastructure.
	ClassOOB VariantClass = "oob"
	// ClassRedirect exercises the target's redirect handling; the final hop
	// stays on the OOB host unless the intranet mode is explicitly enabled.
	ClassRedirect VariantClass = "redirect"
	// ClassRebind uses the authoritative DNS state machine to hand out a
	// public answer first and an internal answer afterwards.
	ClassRebind VariantClass = "rebind"
	// ClassIntranet targets link-local/cloud metadata or RFC1918 addresses
	// directly. Read-only by construction but only emitted in full mode.
	ClassIntranet VariantClass = "intranet"
)

// Variant is one concrete payload URL/hostname injected into one parameter.
type Variant struct {
	ID          string       `json:"id"`
	Class       VariantClass `json:"class"`
	Description string       `json:"description"`
	// URL is the value injected into the target parameter.
	URL string `json:"url"`
	// Hostname is the name the target is expected to resolve; empty when the
	// variant carries a bare IP payload.
	Hostname string `json:"hostname,omitempty"`
	// Intranet is true when triggering the variant can cause the target to
	// talk to an address outside the OOB infrastructure.
	Intranet bool `json:"intranet,omitempty"`
}

// JobContext is the identity encoded into every OOB token. Because the token
// is self-describing (and HMAC protected), a callback arriving days later can
// still be attributed to the exact service / endpoint / parameter / variant
// even if the scanner process that scheduled it is long gone.
type JobContext struct {
	Version    uint8  `json:"v"`
	TaskID     uint64 `json:"task_id"`
	Nonce      uint64 `json:"nonce"`
	RunID      string `json:"run_id"`
	ServiceID  string `json:"service_id"`
	EndpointID string `json:"endpoint_id"`
	Param      string `json:"param"`
	VariantID  string `json:"variant_id"`
}

type EventKind string

const (
	EventDNS   EventKind = "dns"
	EventHTTP  EventKind = "http"
	EventHTTPS EventKind = "https"
)

// Event is one observed interaction with the OOB infrastructure.
type Event struct {
	Seq        uint64    `json:"seq"`
	Time       time.Time `json:"time"`
	Kind       EventKind `json:"kind"`
	Token      string    `json:"token"`
	Trusted    bool      `json:"trusted"`
	RemoteAddr string    `json:"remote_addr"`
	// DNS fields.
	DNSName    string   `json:"dns_name,omitempty"`
	DNSQType   string   `json:"dns_qtype,omitempty"`
	DNSAnswers []string `json:"dns_answers,omitempty"`
	// HTTP fields.
	Scheme      string            `json:"scheme,omitempty"`
	Method      string            `json:"method,omitempty"`
	Host        string            `json:"host,omitempty"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyExcerpt string            `json:"body_excerpt,omitempty"`
	Marker      string            `json:"marker,omitempty"`
	Hops        int               `json:"hops,omitempty"`
}

// Severity levels used in findings.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Confidence string

const (
	Confirmed Confidence = "confirmed"
	Likely    Confidence = "likely"
	Potential Confidence = "potential"
)

// Finding is the correlated verdict for one job.
type Finding struct {
	ServiceID  string       `json:"service_id"`
	EndpointID string       `json:"endpoint_id"`
	Param      string       `json:"param"`
	VariantID  string       `json:"variant_id"`
	Class      VariantClass `json:"class"`
	Severity   Severity     `json:"severity"`
	Confidence Confidence   `json:"confidence"`
	Detail     string       `json:"detail"`
	Events     []Event      `json:"events"`
}
