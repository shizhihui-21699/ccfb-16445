// Command scanner runs SSRF detection jobs from a manifest and correlates the
// results with the OOB infrastructure.
//
// Subcommands:
//
//	scan       run a full scan (safe mode by default)
//	reconcile  re-poll the OOB server for late callbacks of a previous run
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ssrf-platform/internal/engine"
	"ssrf-platform/internal/manifest"
	"ssrf-platform/internal/oob"
	"ssrf-platform/internal/payload"
	"ssrf-platform/internal/safeclient"
)

type commonFlags struct {
	manifestPath   string
	oobURL         string
	apiKey         string
	domain         string
	secret         string
	publicIP       string
	httpPort       int
	httpsPort      int
	metadataIP     string
	internalTarget string
	outDir         string
	allowCIDRs     string
	blockCIDRs     string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "reconcile":
		runReconcile(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  scanner scan       [flags]   run a scan described by a manifest
  scanner reconcile  [flags]   collect late OOB callbacks for a prior run

Run "scanner <subcommand> -h" for its flags.
`)
}

func bindCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.StringVar(&c.manifestPath, "manifest", "manifests/example.json", "path to the target manifest")
	fs.StringVar(&c.oobURL, "oob-url", envOr("OOB_COLLECTOR_URL", "http://127.0.0.1:8080"), "OOB collector base URL")
	fs.StringVar(&c.apiKey, "api-key", envOr("OOB_API_KEY", "dev-only-key"), "OOB API key")
	fs.StringVar(&c.domain, "domain", envOr("OOB_DOMAIN", "oob.example.test"), "OOB apex domain")
	fs.StringVar(&c.secret, "secret", envOr("OOB_SECRET", "dev-only-change-me"), "HMAC secret shared with oobd")
	fs.StringVar(&c.publicIP, "public-ip", envOr("OOB_PUBLIC_IP", "127.0.0.1"), "OOB collector public IP (rebind first answer)")
	fs.IntVar(&c.httpPort, "http-port", 8080, "OOB collector HTTP port embedded in payload URLs")
	fs.IntVar(&c.httpsPort, "https-port", 8443, "OOB collector HTTPS port embedded in payload URLs")
	fs.StringVar(&c.metadataIP, "metadata-ip", "169.254.169.254", "cloud metadata IP used by intranet variants")
	fs.StringVar(&c.internalTarget, "internal-target", "127.0.0.1", "internal target for rebind/redirect variants")
	fs.StringVar(&c.outDir, "out", "runs/latest", "output directory for jobs.jsonl and report.json")
	fs.StringVar(&c.allowCIDRs, "allow-cidrs", "", "comma-separated scanner dial allow-list (default: allow except blocks)")
	fs.StringVar(&c.blockCIDRs, "block-cidrs", "", "comma-separated extra scanner dial block-list")
	return c
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	c := bindCommon(fs)
	mode := fs.String("mode", "safe", "scan mode: safe (OOB-only) or full (adds intranet/metadata probes)")
	workers := fs.Int("workers", 8, "concurrent probe senders")
	rate := fs.Float64("rate", 5.0, "max probes per second")
	window := fs.Duration("window", 2*time.Minute, "observation window after all probes are sent")
	poll := fs.Duration("poll", 5*time.Second, "OOB polling interval")
	budget := fs.Int("intranet-budget", 200, "hard cap on intranet-class requests (full mode)")
	runID := fs.String("run-id", "", "explicit run id (default: generated)")
	_ = fs.Parse(args)

	m, err := manifest.Load(c.manifestPath)
	fatalIf("manifest", err)

	pol, err := safeclient.ParsePolicy(splitCSV(c.allowCIDRs), splitCSV(c.blockCIDRs))
	fatalIf("policy", err)
	client := safeclient.New(pol, false)

	gen := payload.New(payload.Config{
		Domain:         c.domain,
		Secret:         []byte(c.secret),
		HTTPPort:       c.httpPort,
		HTTPSPort:      c.httpsPort,
		PublicIP:       c.publicIP,
		MetadataIP:     c.metadataIP,
		InternalTarget: c.internalTarget,
	})
	id := *runID
	if id == "" {
		id = "run-" + randHex(4) + "-" + time.Now().UTC().Format("20060102T150405Z")
	}

	cfg := engine.Config{
		Manifest:          m,
		Generator:         gen,
		OOBClient:         oob.New(c.oobURL, c.apiKey),
		HTTPClient:        client,
		Policy:            pol,
		Mode:              engine.Mode(*mode),
		RunID:             id,
		OutDir:            c.outDir,
		Workers:           *workers,
		RatePerSecond:     *rate,
		ObservationWindow: *window,
		PollInterval:      *poll,
		IntranetBudget:    *budget,
		Secret:            []byte(c.secret),
		MetadataIP:        c.metadataIP,
		InternalTarget:    c.internalTarget,
	}

	ctx, stop := signalContext()
	defer stop()
	eng, err := engine.New(cfg)
	fatalIf("engine", err)
	report, err := eng.Run(ctx)
	if err != nil {
		logf("scan ended with error: %v", err)
		os.Exit(1)
	}
	printSummary(report)
	logf("report written to %s/report.json", c.outDir)
}

func runReconcile(args []string) {
	fs := flag.NewFlagSet("reconcile", flag.ExitOnError)
	c := bindCommon(fs)
	mode := fs.String("mode", "safe", "mode recorded for the report (safe/full)")
	_ = fs.Parse(args)

	m, err := manifest.Load(c.manifestPath)
	fatalIf("manifest", err)
	pol, err := safeclient.ParsePolicy(splitCSV(c.allowCIDRs), splitCSV(c.blockCIDRs))
	fatalIf("policy", err)
	gen := payload.New(payload.Config{
		Domain:         c.domain,
		Secret:         []byte(c.secret),
		HTTPPort:       c.httpPort,
		HTTPSPort:      c.httpsPort,
		PublicIP:       c.publicIP,
		MetadataIP:     c.metadataIP,
		InternalTarget: c.internalTarget,
	})
	cfg := engine.Config{
		Manifest:       m,
		Generator:      gen,
		OOBClient:      oob.New(c.oobURL, c.apiKey),
		HTTPClient:     safeclient.New(pol, false),
		Policy:         pol,
		Mode:           engine.Mode(*mode),
		RunID:          "reconcile",
		OutDir:         c.outDir,
		Secret:         []byte(c.secret),
		MetadataIP:     c.metadataIP,
		InternalTarget: c.internalTarget,
	}
	ctx, stop := signalContext()
	defer stop()
	report, err := engine.Reconcile(ctx, cfg)
	fatalIf("reconcile", err)
	printSummary(report)
}

func printSummary(r *engine.Report) {
	fmt.Println("--- scan summary ---")
	fmt.Printf("run:               %s (mode=%s)\n", r.RunID, r.Mode)
	fmt.Printf("jobs:              %d (intranet sent: %d)\n", r.Summary.TotalJobs, r.Summary.IntranetSent)
	fmt.Printf("confirmed findings %d across %d distinct target(s)\n", r.Summary.ConfirmedSSRF, r.Summary.DistinctTargets)
	if len(r.Summary.BySeverity) > 0 {
		fmt.Printf("by severity:       %v\n", r.Summary.BySeverity)
	}
	if len(r.Summary.ByVariant) > 0 {
		fmt.Printf("by variant:        %v\n", r.Summary.ByVariant)
	}
	for _, f := range r.Findings {
		fmt.Printf("[%s/%s] %s #%s variant=%s -> %s (%s)\n",
			f.Severity, f.Confidence, f.ServiceID, f.EndpointID, f.Param, f.VariantID, f.Detail)
	}
	for _, u := range r.Unconfirmed {
		fmt.Printf("[review] %s #%s param=%s variant=%s: %s\n",
			u.ServiceID, u.EndpointID, u.Param, u.VariantID, u.Reason)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatalIf(scope string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", scope, err)
		os.Exit(1)
	}
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
