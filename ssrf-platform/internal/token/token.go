// Package token implements the self-describing, HMAC-protected correlation
// tokens embedded in every OOB hostname and URL.
//
// Wire layout (before Base32):
//
//	uvarint version, uvarint taskID, uvarint nonce,
//	4 length-prefixed strings: runID, serviceID, endpointID, param, variantID
//	10 bytes HMAC-SHA256(secret, payload)
//
// The whole blob is lowercase Raw-Base32. For DNS usage it is split into
// labels of at most 50 characters so no 63-byte label limit is ever hit.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"

	"ssrf-platform/internal/types"
)

const hmacLen = 10

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	ErrBadToken = errors.New("token: invalid or untrusted token")
	ErrNoToken  = errors.New("token: no token present in name")
)

func appendString(b []byte, s string) []byte {
	b = appendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func readString(b []byte) (string, []byte, error) {
	n, rest := readUvarint(b)
	if n == 0 && len(rest) == len(b) {
		return "", nil, ErrBadToken
	}
	if uint64(len(rest)) < n {
		return "", nil, ErrBadToken
	}
	return string(rest[:n]), rest[n:], nil
}

// min-content uvarint (avoids pulling binary's bulkier API surface).
func appendUvarint(b []byte, x uint64) []byte {
	for x >= 0x80 {
		b = append(b, byte(x)|0x80)
		x >>= 7
	}
	return append(b, byte(x))
}

func readUvarint(b []byte) (uint64, []byte) {
	var x uint64
	var s uint
	for i, c := range b {
		if c < 0x80 {
			return x | uint64(c)<<s, b[i+1:]
		}
		x |= uint64(c&0x7f) << s
		s += 7
		if s >= 64 {
			return 0, nil
		}
	}
	return 0, nil
}

func mac(secret, payload []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	return h.Sum(nil)[:hmacLen]
}

// Encode returns the compact, single-piece token string.
func Encode(c types.JobContext, secret []byte) string {
	var b []byte
	b = appendUvarint(b, uint64(c.Version))
	b = appendUvarint(b, c.TaskID)
	b = appendUvarint(b, c.Nonce)
	b = appendString(b, c.RunID)
	b = appendString(b, c.ServiceID)
	b = appendString(b, c.EndpointID)
	b = appendString(b, c.Param)
	b = appendString(b, c.VariantID)
	b = append(b, mac(secret, b)...)
	return b32.EncodeToString(b)
}

// Decode validates the HMAC and returns the encoded job context.
func Decode(tok string, secret []byte) (types.JobContext, error) {
	raw, err := b32.DecodeString(strings.ToLower(tok))
	if err != nil || len(raw) < hmacLen {
		return types.JobContext{}, ErrBadToken
	}
	payload, sig := raw[:len(raw)-hmacLen], raw[len(raw)-hmacLen:]
	if !hmac.Equal(sig, mac(secret, payload)) {
		return types.JobContext{}, ErrBadToken
	}
	var c types.JobContext
	var ok bool
	rest := payload
	read := func() (uint64, bool) {
		var v uint64
		v, rest = readUvarint(rest)
		if rest == nil {
			return 0, false
		}
		return v, true
	}
	v, ok := read()
	if !ok {
		return c, ErrBadToken
	}
	c.Version = uint8(v)
	if c.TaskID, ok = read(); !ok {
		return c, ErrBadToken
	}
	if c.Nonce, ok = read(); !ok {
		return c, ErrBadToken
	}
	for _, dst := range []*string{&c.RunID, &c.ServiceID, &c.EndpointID, &c.Param, &c.VariantID} {
		*dst, rest, err = readString(rest)
		if err != nil {
			return c, ErrBadToken
		}
	}
	if len(rest) != 0 {
		return c, ErrBadToken
	}
	return c, nil
}

// DecodeOrRaw returns the flat token and, when HMAC verification succeeds,
// its context plus trusted=true. A malformed or forged token is still
// returned raw with trusted=false so the server can log the attempt.
func DecodeOrRaw(tok string, secret []byte) (string, types.JobContext, bool) {
	tok = strings.ToLower(tok)
	if _, err := b32.DecodeString(tok); err != nil {
		return "", types.JobContext{}, false
	}
	ctx, err := Decode(tok, secret)
	if err != nil {
		return tok, types.JobContext{}, false
	}
	return tok, ctx, true
}

// DNSName splits the token into DNS-label-safe chunks under domain.
func DNSName(c types.JobContext, domain string, secret []byte) string {
	tok := Encode(c, secret)
	var labels []string
	for len(tok) > 50 {
		labels, tok = append(labels, tok[:50]), tok[50:]
	}
	labels = append(labels, tok)
	return strings.Join(append(labels, domain), ".")
}

// Extract pulls a token out of an arbitrary DNS name (labels may have been
// split) and, when secret is non-nil, verifies it. It returns the raw token
// plus the decoded context; the token is returned even when verification
// fails so the server can log the attempt as untrusted.
func Extract(name, domain string, secret []byte) (string, types.JobContext, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if !strings.HasSuffix(name, "."+domain) && name != domain {
		return "", types.JobContext{}, false
	}
	prefix := strings.TrimSuffix(name, domain)
	prefix = strings.TrimSuffix(prefix, ".")
	if prefix == "" {
		return "", types.JobContext{}, false
	}
	flat := strings.ReplaceAll(prefix, ".", "")
	if _, err := b32.DecodeString(flat); err != nil {
		return "", types.JobContext{}, false
	}
	ctx, err := Decode(flat, secret)
	if err != nil {
		return flat, types.JobContext{}, false
	}
	return flat, ctx, true
}
