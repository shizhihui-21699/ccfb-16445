// Command oobd runs the out-of-band infrastructure: authoritative DNS server,
// HTTP/HTTPS interaction collector and the authenticated correlation API.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"ssrf-platform/internal/collector"
	miekdns "ssrf-platform/internal/dnssrv"
	"ssrf-platform/internal/store"
)

func main() {
	domain := flag.String("domain", envOr("OOB_DOMAIN", "oob.example.test"), "apex OOB domain (authoritative zone)")
	dnsUDP := flag.String("dns-udp", envOr("OOB_DNS_UDP", ":5354"), "DNS UDP listen address")
	dnsTCP := flag.String("dns-tcp", envOr("OOB_DNS_TCP", ":5354"), "DNS TCP listen address")
	httpAddr := flag.String("http", envOr("OOB_HTTP", ":8080"), "HTTP listen address")
	httpsAddr := flag.String("https", envOr("OOB_HTTPS", ":8443"), "HTTPS listen address (skipped when empty)")
	publicIP := flag.String("public-ip", envOr("OOB_PUBLIC_IP", "127.0.0.1"), "public IP returned for tokenized A queries and rebind first answer")
	secret := flag.String("secret", envOr("OOB_SECRET", "dev-only-change-me"), "HMAC secret for token verification")
	apiKey := flag.String("api-key", envOr("OOB_API_KEY", "dev-only-key"), "shared key for the correlation API")
	dataDir := flag.String("data-dir", envOr("OOB_DATA_DIR", "./oob-data"), "directory for the event journal and rebind plans")
	allowIntranetRedirects := flag.Bool("allow-intranet-redirects", false, "permit /r to redirect outside the OOB domain (dangerous)")
	noTLS := flag.Bool("no-tls", false, "disable the HTTPS listener")
	flag.Parse()

	st, err := store.Open(*dataDir, 256)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	dnsServer, err := miekdns.New(miekdns.Config{
		Domain:    *domain,
		ListenUDP: *dnsUDP,
		ListenTCP: *dnsTCP,
		PublicIP:  *publicIP,
		Secret:    []byte(*secret),
		Store:     st,
		DataDir:   *dataDir,
	})
	if err != nil {
		log.Fatalf("dns: %v", err)
	}

	coll := collector.New(collector.Config{
		Domain:                 *domain,
		Secret:                 []byte(*secret),
		Store:                  st,
		APIKey:                 *apiKey,
		AllowIntranetRedirects: *allowIntranetRedirects,
		Rebind:                 rebindAdapter{srv: dnsServer},
	})

	errCh := make(chan error, 2)
	go func() { errCh <- dnsServer.ListenAndServe() }()

	var tlsCfg *tls.Config
	if !*noTLS {
		tlsCfg, err = collector.SelfSignedTLSConfig(*domain, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
	}
	go func() { errCh <- coll.ListenAndServe(*httpAddr, tlsCfg, *httpsAddr) }()

	log.Printf("oobd ready: domain=%s dns=%s/%s http=%s https=%v data=%s",
		*domain, *dnsUDP, *dnsTCP, *httpAddr, !*noTLS, *dataDir)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	}
	_ = dnsServer.Close()
	_ = coll.Close()
	fmt.Println("oobd stopped")
}

// rebindAdapter bridges the collector API to the DNS server's plan store.
type rebindAdapter struct{ srv *miekdns.Server }

func (a rebindAdapter) RegisterPlan(token, publicIP string, internalIPs []string, ttl uint32) error {
	return a.srv.RegisterPlan(miekdns.RebindPlan{
		Token: token, PublicIP: publicIP, InternalIPs: internalIPs, TTL: ttl,
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
