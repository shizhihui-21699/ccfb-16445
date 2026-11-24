// Package store is the OOB server's interaction store: a bounded in-memory
// index for hot correlation plus an append-only JSONL journal so events
// survive restarts and late callbacks can be replayed into future runs.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"ssrf-platform/internal/types"
)

var ErrNotFound = errors.New("store: token not found")

// Store indexes events by the flat token they belong to.
type Store struct {
	mu        sync.RWMutex
	byToken   map[string][]types.Event
	seqs      uint64
	journal   *os.File
	writer    *bufio.Writer
	maxPerTok int
}

// Open creates/opens the JSONL journal at dir/events.jsonl and replays it.
func Open(dir string, maxPerToken int) (*Store, error) {
	if maxPerToken <= 0 {
		maxPerToken = 128
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s := &Store{byToken: make(map[string][]types.Event), journal: f, writer: bufio.NewWriter(f), maxPerTok: maxPerToken}
	if err := s.replay(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) replay() error {
	// Re-read from the beginning; the file is opened O_APPEND for writes.
	in, err := os.Open(s.journal.Name())
	if err != nil {
		return err
	}
	defer in.Close()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev types.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue // tolerate a torn final line
		}
		s.index(ev, false)
	}
	return sc.Err()
}

func (s *Store) index(ev types.Event, persist bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seqs++
	ev.Seq = s.seqs
	list := s.byToken[ev.Token]
	if len(list) < s.maxPerTok {
		s.byToken[ev.Token] = append(list, ev)
	}
	if persist {
		line, _ := json.Marshal(ev)
		_, _ = s.writer.Write(line)
		_ = s.writer.WriteByte('\n')
		_ = s.writer.Flush()
	}
}

// Record indexes and journals one event.
func (s *Store) Record(ev types.Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	s.index(ev, true)
}

// Lookup returns all events for a flat token, newest last.
func (s *Store) Lookup(tok string) ([]types.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	evs, ok := s.byToken[tok]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]types.Event, len(evs))
	copy(out, evs)
	return out, nil
}

// Since returns events strictly newer than the given sequence number.
func (s *Store) Since(seq uint64, limit int) []types.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []types.Event
	for _, list := range s.byToken {
		for _, ev := range list {
			if ev.Seq > seq {
				out = append(out, ev)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Close flushes and closes the journal.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writer.Flush(); err != nil {
		return err
	}
	return s.journal.Close()
}
