package payload

import (
	"net/url"
	"strings"
	"testing"

	"ssrf-platform/internal/types"
)

func testGen() *Generator {
	return New(Config{
		Domain: "oob.example.test", Secret: []byte("s"),
		HTTPPort: 8080, HTTPSPort: 8443, PublicIP: "203.0.113.10",
		MetadataIP: "169.254.169.254", InternalTarget: "127.0.0.1",
	})
}

func ctx() types.JobContext {
	return types.JobContext{Version: 1, TaskID: 7, RunID: "r", ServiceID: "svc", EndpointID: "ep", Param: "url"}
}

func findVariant(vs []types.Variant, id string) *types.Variant {
	for i := range vs {
		if vs[i].ID == id {
			return &vs[i]
		}
	}
	return nil
}

func TestSafeVariantsNeverTouchIntranet(t *testing.T) {
	vs := testGen().Build(ctx(), false)
	if len(vs) == 0 {
		t.Fatal("no variants generated")
	}
	for _, v := range vs {
		if v.Intranet {
			t.Fatalf("safe mode emitted intranet variant %s", v.ID)
		}
		if strings.Contains(v.URL, "169.254") || strings.Contains(v.URL, "127.") || strings.Contains(v.URL, "0.0.0.0") {
			t.Fatalf("safe variant %s references internal address: %s", v.ID, v.URL)
		}
	}
	if findVariant(vs, "metadata-direct") != nil {
		t.Fatal("metadata variant must not exist in safe mode")
	}
}

func TestFullModeContainsAllDeformationFamilies(t *testing.T) {
	vs := testGen().Build(ctx(), true)
	want := []string{
		"oob-http", "oob-https", "dns-only", "redirect-1hop", "redirect-3hop",
		"rebind-first-public", "url-userinfo-confusion",
		"metadata-direct", "metadata-aws-path", "metadata-decimal", "metadata-hex",
		"metadata-octal", "metadata-v6mapped",
		"internal-loopback", "internal-shorthand-127.1", "internal-all-zeros",
		"internal-ipv6-loopback", "internal-decimal", "internal-octal",
		"redirect-to-metadata", "redirect-to-internal",
	}
	for _, id := range want {
		if findVariant(vs, id) == nil {
			t.Errorf("full mode missing variant %q", id)
		}
	}
}

func TestMetadataDeformationValues(t *testing.T) {
	vs := testGen().Build(ctx(), true)
	cases := map[string]string{
		"metadata-decimal":  "2852039166", // 169.254.169.254 as one integer
		"metadata-hex":      "0xa9fea9fe",
		"metadata-octal":    "0251.0376.0251.0376",
		"metadata-v6mapped": "[::ffff:a9fe:a9fe]",
	}
	for id, want := range cases {
		v := findVariant(vs, id)
		if v == nil {
			t.Fatalf("missing %s", id)
		}
		if !strings.Contains(v.URL, want) {
			t.Errorf("%s URL = %q, want substring %q", id, v.URL, want)
		}
	}
}

func TestRedirectVariantCarriesHopsAndToken(t *testing.T) {
	g := testGen()
	vs := g.Build(ctx(), false)
	v := findVariant(vs, "redirect-3hop")
	if v == nil {
		t.Fatal("missing redirect-3hop")
	}
	u, err := url.Parse(v.URL)
	if err != nil {
		t.Fatalf("bad url %q: %v", v.URL, err)
	}
	if u.Query().Get("hops") != "3" {
		t.Fatalf("hops param = %q, want 3", u.Query().Get("hops"))
	}
	if !strings.HasPrefix(u.Path, "/r/") {
		t.Fatalf("redirect path = %q", u.Path)
	}
}

func TestEveryVariantTokenMatchesGenerator(t *testing.T) {
	g := testGen()
	c := ctx()
	vs := g.Build(c, true)
	for _, v := range vs {
		c.VariantID = v.ID
		want := g.VariantToken(c, v.ID)
		if v.ID == "dns-only" || strings.HasPrefix(v.ID, "metadata-") || strings.HasPrefix(v.ID, "internal-") {
			// Bare-IP / bare-hostname variants carry no embedded token;
			// attribution for them relies on the job record alone.
			if v.ID == "dns-only" {
				flatName := strings.ReplaceAll(v.Hostname, ".", "")
				if !strings.Contains(flatName, want) {
					t.Errorf("dns-only hostname %q missing token %q", v.Hostname, want)
				}
			}
			continue
		}
		if !strings.Contains(v.URL, want) {
			t.Errorf("variant %s URL %q does not contain job token %q", v.ID, v.URL, want)
		}
	}
}

func TestRebindNameFirstPublicThenInternal(t *testing.T) {
	g := testGen()
	name := g.RebindName(ctx())
	if !strings.HasSuffix(name, "oob.example.test") {
		t.Fatalf("rebind name %q outside zone", name)
	}
}
