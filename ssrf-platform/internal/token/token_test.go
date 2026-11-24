package token

import (
	"strings"
	"testing"

	"ssrf-platform/internal/types"
)

func sampleCtx() types.JobContext {
	return types.JobContext{
		Version: 1, TaskID: 4242, Nonce: 99, RunID: "run-1",
		ServiceID: "preview-svc", EndpointID: "fetch", Param: "image_url", VariantID: "oob-http",
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	secret := []byte("unit-secret")
	c := sampleCtx()
	tok := Encode(c, secret)
	if tok == "" || tok != strings.ToLower(tok) {
		t.Fatalf("token must be non-empty lowercase, got %q", tok)
	}
	got, err := Decode(tok, secret)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != c {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", got, c)
	}
}

func TestDecodeRejectsWrongSecretAndTampering(t *testing.T) {
	tok := Encode(sampleCtx(), []byte("a"))
	if _, err := Decode(tok, []byte("b")); err != ErrBadToken {
		t.Fatalf("wrong secret: want ErrBadToken, got %v", err)
	}
	// Flip one character of the payload portion.
	tampered := tok[:len(tok)-2]
	switch tok[len(tok)-2] {
	case 'a':
		tampered += "b"
	default:
		tampered += "a"
	}
	tampered += tok[len(tok)-1:]
	if _, err := Decode(tampered, []byte("a")); err != ErrBadToken {
		t.Fatalf("tampered token: want ErrBadToken, got %v", err)
	}
}

func TestDNSNameLabelsAndExtract(t *testing.T) {
	secret := []byte("k")
	domain := "oob.example.test"
	c := sampleCtx()
	name := DNSName(c, domain, secret)
	if strings.Count(name, ".") < 1 {
		t.Fatalf("bad dns name %q", name)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			t.Fatalf("label too long (%d): %q", len(label), label)
		}
	}
	flat, got, trusted := Extract(name, domain, secret)
	if !trusted || flat == "" {
		t.Fatalf("extract failed: trusted=%v flat=%q", trusted, flat)
	}
	if got.ServiceID != c.ServiceID || got.Param != c.Param || got.VariantID != c.VariantID {
		t.Fatalf("extracted context mismatch: %+v", got)
	}
}

func TestExtractForeignDomainAndForgedToken(t *testing.T) {
	secret := []byte("k")
	if _, _, ok := Extract("foo.other.test.", "oob.example.test", secret); ok {
		t.Fatal("foreign domain must not extract")
	}
	name := DNSName(sampleCtx(), "oob.example.test", secret)
	if _, _, trusted := Extract(name, "oob.example.test", []byte("other")); trusted {
		t.Fatal("HMAC mismatch must report trusted=false")
	}
}

func TestLongContextStaysLabelSafe(t *testing.T) {
	secret := []byte("k")
	c := sampleCtx()
	c.ServiceID = strings.Repeat("svc", 30)
	c.Param = strings.Repeat("p", 40)
	name := DNSName(c, "oob.example.test", secret)
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			t.Fatalf("long context produced oversized label %q (%d)", label, len(label))
		}
	}
	if _, _, trusted := Extract(name, "oob.example.test", secret); !trusted {
		t.Fatal("long context token must still verify")
	}
}
