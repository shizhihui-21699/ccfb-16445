// Command demo-target is a small intentionally-vulnerable service used to
// exercise the platform end to end. It mirrors three real-world shapes:
//
//	GET  /preview/fetch?url=     synchronous server-side fetch (SSRF)
//	POST /webhook  {"url": ...}  queued fetch executed by an async worker
//	GET  /safe/render?url=       allow-list that only blocks literal internals
//
// It is a test fixture, never deploy it outside a lab.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type queued struct {
	mu   sync.Mutex
	urls []string
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9099", "listen address")
	asyncDelay := flag.Duration("delay", 8*time.Second, "async webhook worker delay")
	dnsServer := flag.String("dns-server", "", "resolver for outbound fetches, e.g. 127.0.0.1:5354 (lab NS delegation substitute)")
	flag.Parse()

	client := buildClient(*dnsServer)
	q := &queued{}
	go q.worker(*asyncDelay, client)

	mux := http.NewServeMux()
	mux.HandleFunc("/preview/fetch", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		resp, err := client.Get(u)
		if err != nil {
			http.Error(w, "fetch error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			URL string `json:"url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		q.mu.Lock()
		q.urls = append(q.urls, in.URL)
		q.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("/safe/render", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if strings.Contains(u, "169.254") || strings.Contains(u, "127.") || strings.Contains(u, "0.0.0.0") {
			http.Error(w, "internal addresses blocked", http.StatusForbidden)
			return
		}
		resp, err := client.Get(u)
		if err != nil {
			http.Error(w, "fetch error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		w.WriteHeader(http.StatusOK)
	})
	log.Printf("demo target listening on %s (async delay %s, dns=%q)", *addr, *asyncDelay, *dnsServer)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func buildClient(dnsServer string) *http.Client {
	tr := &http.Transport{
		ResponseHeaderTimeout: 6 * time.Second,
		TLSClientConfig:       insecureTLS(),
	}
	if dnsServer != "" {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, network, dnsServer)
			},
		}
		dialer := &net.Dialer{Timeout: 4 * time.Second, Resolver: resolver}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if ip := net.ParseIP(host); ip != nil {
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (q *queued) worker(delay time.Duration, client *http.Client) {
	for {
		time.Sleep(delay)
		q.mu.Lock()
		pending := append([]string(nil), q.urls...)
		q.urls = nil
		q.mu.Unlock()
		for _, u := range pending {
			resp, err := client.Get(u)
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
			}
		}
	}
}
