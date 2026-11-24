// Package engine is the scan orchestrator and correlation engine.
//
// Pipeline:
//
//  1. expand manifest × parameters × variants into jobs; every job owns a
//     unique, HMAC-protected token;
//  2. arm rebind plans, then deliver probes through the guarded HTTP client
//     with a global rate limiter and intranet-request budget;
//  3. poll the OOB collector throughout the observation window and again at
//     the end, matching trusted events back to exact jobs;
//  4. combine OOB evidence with synchronous response markers into findings
//     that name service / endpoint / parameter / variant;
//  5. persist jobs and findings so "reconcile" can attribute callbacks that
//     arrive hours or days later.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ssrf-platform/internal/injector"
	"ssrf-platform/internal/manifest"
	"ssrf-platform/internal/oob"
	"ssrf-platform/internal/payload"
	"ssrf-platform/internal/safeclient"
	"ssrf-platform/internal/types"
)

// Mode controls which variants are emitted.
type Mode string

const (
	// ModeSafe only emits variants that contact the OOB infrastructure.
	ModeSafe Mode = "safe"
	// ModeFull additionally emits read-only intranet/metadata variants.
	ModeFull Mode = "full"
)

// Config configures a run.
type Config struct {
	Manifest          *manifest.Manifest
	Generator         *payload.Generator
	OOBClient         *oob.Client
	HTTPClient        *http.Client
	Policy            *safeclient.Policy
	Mode              Mode
	RunID             string
	OutDir            string
	Workers           int
	RatePerSecond     float64
	ObservationWindow time.Duration
	PollInterval      time.Duration
	IntranetBudget    int // hard cap on intranet-class requests, 0 disables
	Secret            []byte
	MetadataIP        string
	InternalTarget    string
}

type job struct {
	Context  types.JobContext `json:"context"`
	Variant  types.Variant    `json:"variant"`
	Service  manifest.Service `json:"service"`
	Endpoint manifest.Endpoint
	Param    manifest.Param
	Token    string `json:"token"`
	// populated after sending
	Status       int    `json:"status,omitempty"`
	RespExcerpt  string `json:"resp_excerpt,omitempty"`
	MarkerInBody bool   `json:"marker_in_body,omitempty"`
	SentAt       time.Time
	SendErr      string `json:"send_err,omitempty"`
}

// Engine holds run state.
type Engine struct {
	cfg Config

	mu        sync.RWMutex
	jobs      []*job
	byToken   map[string]*job
	events    map[string][]types.Event
	intranetN int
	limiter   *rateLimiter
}

// New validates the config and constructs an engine.
func New(cfg Config) (*Engine, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = 5
	}
	if cfg.ObservationWindow <= 0 {
		cfg.ObservationWindow = 2 * time.Minute
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeSafe
	}
	if cfg.Mode != ModeSafe && cfg.Mode != ModeFull {
		return nil, fmt.Errorf("engine: unknown mode %q", cfg.Mode)
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return nil, err
	}
	return &Engine{
		cfg:     cfg,
		byToken: make(map[string]*job),
		events:  make(map[string][]types.Event),
		limiter: newRateLimiter(cfg.RatePerSecond),
	}, nil
}

// Config returns the engine configuration, used to build a follow-up
// reconciliation run with identical secrets and endpoints.
func (e *Engine) Config() Config { return e.cfg }

// Run executes the full scan and writes reports under OutDir.
func (e *Engine) Run(ctx context.Context) (*Report, error) {
	if err := e.expand(); err != nil {
		return nil, err
	}
	if err := e.persistJobs(); err != nil {
		return nil, err
	}
	if err := e.deliver(ctx); err != nil {
		return nil, err
	}
	// Re-persist so delivery outcomes (status codes, errors, budget skips)
	// survive for post-mortems and reconciliation.
	if err := e.persistJobs(); err != nil {
		return nil, err
	}
	if err := e.observe(ctx); err != nil {
		return nil, err
	}
	report := e.buildReport()
	if err := e.writeReport(report); err != nil {
		return nil, err
	}
	return report, nil
}

func (e *Engine) expand() error {
	var taskID uint64
	includeIntranet := e.cfg.Mode == ModeFull
	for _, svc := range e.cfg.Manifest.Services {
		for _, ep := range svc.Endpoints {
			for _, p := range ep.Params {
				// The full context (including TaskID/Nonce) is passed to the
				// generator, so every embedded token is identical to the job
				// token computed below and OOB events correlate exactly.
				taskID++
				jc := types.JobContext{
					Version:    1,
					TaskID:     taskID,
					Nonce:      taskID*1_000_003 + uint64(time.Now().UnixNano()%1_000_003),
					RunID:      e.cfg.RunID,
					ServiceID:  svc.ID,
					EndpointID: ep.ID,
					Param:      p.Name,
				}
				for _, v := range e.cfg.Generator.Build(jc, includeIntranet) {
					jc.VariantID = v.ID
					tok := e.cfg.Generator.VariantToken(jc, v.ID)
					j := &job{Context: jc, Variant: v, Service: svc, Endpoint: ep, Param: p, Token: tok}
					e.jobs = append(e.jobs, j)
					e.byToken[tok] = j
				}
			}
		}
	}
	if len(e.jobs) == 0 {
		return errors.New("engine: no jobs generated")
	}
	return nil
}

func (e *Engine) persistJobs() error {
	f, err := os.OpenFile(filepath.Join(e.cfg.OutDir, "jobs.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, j := range e.jobs {
		if err := enc.Encode(j); err != nil {
			return err
		}
	}
	return nil
}

// deliver arms rebind plans and sends every probe.
func (e *Engine) deliver(ctx context.Context) error {
	// Arm all rebind plans first so the DNS state machine is ready before any
	// target resolves the name.
	for _, j := range e.jobs {
		if j.Variant.Class != types.ClassRebind {
			continue
		}
		err := e.cfg.OOBClient.ArmRebind(ctx, oob.RebindPlan{
			Token:       j.Token,
			PublicIP:    e.cfg.Generator.Config().PublicIP,
			InternalIPs: []string{pickInternal(j, e.cfg.InternalTarget, e.cfg.MetadataIP)},
			TTL:         1,
		})
		if err != nil {
			j.SendErr = "arm rebind: " + err.Error()
		}
	}

	sem := make(chan struct{}, e.cfg.Workers)
	var wg sync.WaitGroup
	var wgMu sync.Mutex
	var firstErr error
	for _, j := range e.jobs {
		if err := e.limiter.Wait(ctx); err != nil {
			return err
		}
		if j.Variant.Intranet {
			e.mu.Lock()
			if e.cfg.IntranetBudget > 0 && e.intranetN >= e.cfg.IntranetBudget {
				j.SendErr = "skipped: intranet budget exhausted"
				e.mu.Unlock()
				continue
			}
			e.intranetN++
			e.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(j *job) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := e.sendOne(ctx, j); err != nil {
				wgMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				wgMu.Unlock()
			}
		}(j)
	}
	wg.Wait()
	return firstErr
}

func pickInternal(j *job, internalTarget, metadataIP string) string {
	if strings.Contains(j.Variant.ID, "metadata") && metadataIP != "" {
		return metadataIP
	}
	if internalTarget != "" {
		return internalTarget
	}
	return "127.0.0.1"
}

func (e *Engine) sendOne(ctx context.Context, j *job) error {
	req, err := injector.BuildRequest(j.Service, j.Endpoint, j.Param, j.Variant.URL)
	if err != nil {
		j.SendErr = err.Error()
		return nil // job-level failure, not a run failure
	}
	// Each parameter gets its own request with a fresh trace header so the
	// target side can correlate logs if it wants to.
	req.Header.Set("X-Ssrf-Task-Id", fmt.Sprintf("%d", j.Context.TaskID))
	resp, err := e.cfg.HTTPClient.Do(req.WithContext(ctx))
	j.SentAt = time.Now().UTC()
	if err != nil {
		j.SendErr = err.Error()
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	j.Status = resp.StatusCode
	j.RespExcerpt = string(body)
	j.MarkerInBody = strings.Contains(string(body), "SSRF-PLATFORM-MARKER:"+j.Token)
	return nil
}

// observe polls the collector until the window elapses, indexing trusted
// events by token.
func (e *Engine) observe(ctx context.Context) error {
	deadline := time.Now().Add(e.cfg.ObservationWindow)
	var seq uint64
	ticker := time.NewTicker(e.cfg.PollInterval)
	defer ticker.Stop()
	for {
		if err := e.pollOnce(ctx, &seq); err != nil {
			// Transient API errors must not abort the whole observation.
			fmt.Fprintf(os.Stderr, "engine: poll error: %v\n", err)
		}
		if time.Now().After(deadline) {
			return e.pollOnce(ctx, &seq) // final drain
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (e *Engine) pollOnce(ctx context.Context, seq *uint64) error {
	evs, err := e.cfg.OOBClient.Since(ctx, *seq, 1000)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range evs {
		if ev.Seq <= *seq {
			continue
		}
		*seq = ev.Seq
		if !ev.Trusted {
			continue
		}
		if _, ok := e.byToken[ev.Token]; !ok {
			continue // callback for a different run / unknown token
		}
		e.events[ev.Token] = append(e.events[ev.Token], ev)
	}
	return nil
}

// ---- verdict and reporting -------------------------------------------------

// Report is the persisted scan result.
type Report struct {
	RunID       string           `json:"run_id"`
	Mode        Mode             `json:"mode"`
	GeneratedAt time.Time        `json:"generated_at"`
	Summary     Summary          `json:"summary"`
	Findings    []types.Finding  `json:"findings"`
	Unconfirmed []UnconfirmedJob `json:"unconfirmed_jobs,omitempty"`
}

// Summary aggregates run statistics.
type Summary struct {
	TotalJobs       int            `json:"total_jobs"`
	IntranetSent    int            `json:"intranet_sent"`
	ConfirmedSSRF   int            `json:"confirmed_ssrf"`
	BySeverity      map[string]int `json:"by_severity"`
	ByVariant       map[string]int `json:"by_variant"`
	DistinctTargets int            `json:"distinct_vulnerable_targets"`
}

// UnconfirmedJob keeps the exact probe location for manual follow-up.
type UnconfirmedJob struct {
	ServiceID  string             `json:"service_id"`
	EndpointID string             `json:"endpoint_id"`
	Param      string             `json:"param"`
	VariantID  string             `json:"variant_id"`
	Class      types.VariantClass `json:"class"`
	Reason     string             `json:"reason"`
}

func (e *Engine) buildReport() *Report {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r := &Report{
		RunID:       e.cfg.RunID,
		Mode:        e.cfg.Mode,
		GeneratedAt: time.Now().UTC(),
	}
	r.Summary.BySeverity = map[string]int{}
	r.Summary.ByVariant = map[string]int{}
	targets := map[string]bool{}

	for _, j := range e.jobs {
		evs := e.events[j.Token]
		f, confirmed := e.verdict(j, evs)
		if confirmed {
			r.Findings = append(r.Findings, f)
			r.Summary.ConfirmedSSRF++
			r.Summary.BySeverity[string(f.Severity)]++
			r.Summary.ByVariant[j.Variant.ID]++
			targets[j.Context.ServiceID+"/"+j.Context.EndpointID+"#"+j.Context.Param] = true
			continue
		}
		if j.Variant.Intranet && j.Status != 0 && j.Status != http.StatusForbidden && j.Status != http.StatusBadRequest {
			// Intranet probe reached something and wasn't plainly rejected:
			// surface for manual review rather than silently dropping.
			r.Unconfirmed = append(r.Unconfirmed, UnconfirmedJob{
				ServiceID: j.Context.ServiceID, EndpointID: j.Context.EndpointID,
				Param: j.Context.Param, VariantID: j.Variant.ID, Class: j.Variant.Class,
				Reason: fmt.Sprintf("intranet probe returned HTTP %d without OOB confirmation", j.Status),
			})
		}
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		return severityRank(r.Findings[i].Severity) > severityRank(r.Findings[j].Severity)
	})
	r.Summary.TotalJobs = len(e.jobs)
	r.Summary.IntranetSent = e.intranetN
	r.Summary.DistinctTargets = len(targets)
	return r
}

func (e *Engine) verdict(j *job, evs []types.Event) (types.Finding, bool) {
	f := types.Finding{
		ServiceID:  j.Context.ServiceID,
		EndpointID: j.Context.EndpointID,
		Param:      j.Context.Param,
		VariantID:  j.Variant.ID,
		Class:      j.Variant.Class,
		Events:     evs,
	}
	hasDNS, hasHTTP, hasHTTPS := false, false, false
	var maxHops int
	for _, ev := range evs {
		switch ev.Kind {
		case types.EventDNS:
			hasDNS = true
		case types.EventHTTP:
			hasHTTP = true
		case types.EventHTTPS:
			hasHTTPS = true
		}
		if ev.Hops > maxHops {
			maxHops = ev.Hops
		}
	}

	// Variant semantics take priority: a rebind success is critical even if
	// the target also embedded the marker synchronously.
	switch j.Variant.Class {
	case types.ClassRebind:
		switch {
		case hasHTTP || hasHTTPS:
			f.Severity, f.Confidence = types.SeverityCritical, types.Confirmed
			f.Detail = "HTTP callback after DNS rebind to an internal address"
			return f, true
		case hasDNS:
			f.Severity, f.Confidence = types.SeverityHigh, types.Likely
			f.Detail = "target resolved the rebinding name; post-flip behavior not observed in window"
			return f, true
		default:
			return f, false
		}
	case types.ClassOOB:
		// The dns-only variant is, by design, a resolution-only probe.
		if j.Variant.ID == "dns-only" {
			if hasDNS {
				f.Severity, f.Confidence = types.SeverityMedium, types.Confirmed
				f.Detail = "target resolved the OOB hostname (blind SSRF / URL parsing)"
				return f, true
			}
			return f, false
		}
	case types.ClassIntranet:
		if hasHTTP || hasHTTPS || hasDNS {
			f.Severity, f.Confidence = types.SeverityCritical, types.Confirmed
			f.Detail = "OOB interaction observed from an intranet-class variant"
			return f, true
		}
		return f, false
	}

	// Remaining OOB/redirect variants: strongest signal first.
	switch {
	case hasHTTP || hasHTTPS:
		f.Confidence = types.Confirmed
		if j.Variant.Class == types.ClassRedirect {
			f.Severity = types.SeverityHigh
			f.Detail = fmt.Sprintf("target followed the controlled redirect chain (%d hop(s)) to the OOB collector", maxHops)
		} else {
			f.Severity = types.SeverityHigh
			f.Detail = "target made an outbound HTTP request to the OOB collector"
		}
		return f, true
	// Synchronous marker in the target's own response: the target fetched and
	// embedded our marker page — confirmed regardless of OOB timing.
	case j.MarkerInBody:
		f.Severity, f.Confidence, f.Detail = types.SeverityHigh, types.Confirmed,
			"target response body contains the OOB marker page for this token"
		return f, true
	case hasDNS:
		f.Severity, f.Confidence, f.Detail = types.SeverityMedium, types.Confirmed,
			"target resolved the OOB hostname (blind SSRF / URL parsing)"
		return f, true
	default:
		return f, false
	}
}

func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	default:
		return 0
	}
}

func (e *Engine) writeReport(r *Report) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.cfg.OutDir, "report.json"), raw, 0o600)
}

// ---- late reconciliation ---------------------------------------------------

// Reconcile re-reads the persisted jobs, polls the collector one more time and
// writes an updated report. It is meant to be invoked hours/days after Run for
// services that trigger requests asynchronously.
func Reconcile(ctx context.Context, cfg Config) (*Report, error) {
	e, err := New(cfg)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(cfg.OutDir, "jobs.jsonl"))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var j job
		if err := json.Unmarshal([]byte(line), &j); err != nil {
			continue
		}
		e.jobs = append(e.jobs, &j)
		e.byToken[j.Token] = &j
	}
	var seq uint64
	if err := e.pollOnce(ctx, &seq); err != nil {
		return nil, err
	}
	report := e.buildReport()
	if err := e.writeReport(report); err != nil {
		return nil, err
	}
	return report, nil
}

// ---- simple token-bucket rate limiter --------------------------------------

type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	rate   float64
	last   time.Time
}

func newRateLimiter(rate float64) *rateLimiter {
	return &rateLimiter{tokens: rate, rate: rate, last: time.Now()}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := time.Now()
		r.tokens += now.Sub(r.last).Seconds() * r.rate
		r.last = now
		if r.tokens > r.rate {
			r.tokens = r.rate
		}
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - r.tokens) / r.rate * float64(time.Second))
		r.mu.Unlock()
		if wait <= 0 {
			wait = 10 * time.Millisecond
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
