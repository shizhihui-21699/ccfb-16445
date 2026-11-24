package safeclient

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return n
}

func TestDefaultPolicyBlocksMetadataAndLinkLocal(t *testing.T) {
	p, err := ParsePolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	blocked := []string{
		"169.254.169.254", // cloud metadata
		"169.254.1.1",     // any link-local
		"fe80::1",
		"224.0.0.1",
		"ff02::1",
	}
	for _, ip := range blocked {
		if p.Allowed(net.ParseIP(ip)) {
			t.Errorf("default policy allowed %s", ip)
		}
	}
	allowed := []string{"10.0.0.5", "192.168.1.1", "8.8.8.8", "127.0.0.1"}
	for _, ip := range allowed {
		if !p.Allowed(net.ParseIP(ip)) {
			t.Errorf("default policy blocked ordinary address %s", ip)
		}
	}
}

func TestAllowListMode(t *testing.T) {
	p, err := ParsePolicy([]string{"10.10.0.0/16"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(net.ParseIP("10.10.3.3")) {
		t.Error("allow-listed CIDR member should be permitted")
	}
	if p.Allowed(net.ParseIP("10.11.0.1")) {
		t.Error("address outside allow-list must be blocked")
	}
	// Link-local stays blocked even though the allow list check comes second.
	if p.Allowed(net.ParseIP("169.254.169.254")) {
		t.Error("metadata must remain blocked in allow-list mode")
	}
}

func TestCustomBlockListAndBareIP(t *testing.T) {
	p, err := ParsePolicy(nil, []string{"192.168.99.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(net.ParseIP("192.168.99.7")) {
		t.Error("custom block CIDR not enforced")
	}
	if !p.Allowed(net.ParseIP("192.168.98.7")) {
		t.Error("neighbor CIDR wrongly blocked")
	}
	p2, err := ParsePolicy([]string{"127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Allowed(net.ParseIP("127.0.0.1")) || p2.Allowed(net.ParseIP("127.0.0.2")) {
		t.Error("bare-IP allow entry not treated as /32")
	}
}

func TestClientNeverFollowsRedirects(t *testing.T) {
	p, _ := ParsePolicy(nil, nil)
	c := New(p, false)
	if c.CheckRedirect == nil {
		t.Fatal("redirect policy missing")
	}
	if err := c.CheckRedirect(nil, nil); err == nil {
		t.Error("client must refuse to follow redirects")
	}
}

func TestParsePolicyRejectsGarbage(t *testing.T) {
	if _, err := ParsePolicy([]string{"not-a-cidr"}, nil); err == nil {
		t.Error("garbage CIDR must error")
	}
	if _, err := ParsePolicy(nil, []string{"999.1.1.1/24"}); err == nil {
		t.Error("invalid IP must error")
	}
}

func TestContainsHelperCoverage(t *testing.T) {
	n := mustCIDR(t, "10.0.0.0/8")
	if !n.Contains(net.ParseIP("10.255.255.255")) || n.Contains(net.ParseIP("11.0.0.1")) {
		t.Error("CIDR containment sanity check failed")
	}
}
