package store

import (
	"path/filepath"
	"testing"

	"ssrf-platform/internal/types"
)

func TestRecordLookupAndJournalReplay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	s, err := Open(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	s.Record(types.Event{Kind: types.EventDNS, Token: "tok-a", DNSName: "a.oob.test"})
	s.Record(types.Event{Kind: types.EventHTTP, Token: "tok-a", Path: "/p/tok-a"})
	s.Record(types.Event{Kind: types.EventDNS, Token: "tok-b"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: journal replay must restore the index.
	s2, err := Open(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	evs, err := s2.Lookup("tok-a")
	if err != nil {
		t.Fatalf("lookup after replay: %v", err)
	}
	if len(evs) != 2 || evs[0].Kind != types.EventDNS || evs[1].Kind != types.EventHTTP {
		t.Fatalf("replayed events wrong: %+v", evs)
	}
	if evs[0].Seq == 0 || evs[1].Seq != evs[0].Seq+1 {
		t.Fatalf("sequence numbers not monotonic: %d %d", evs[0].Seq, evs[1].Seq)
	}
}

func TestSinceTail(t *testing.T) {
	s, err := Open(t.TempDir(), 16)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 5; i++ {
		s.Record(types.Event{Token: "t", Kind: types.EventHTTP})
	}
	got := s.Since(2, 0)
	if len(got) != 3 {
		t.Fatalf("Since returned %d events, want 3", len(got))
	}
	for _, ev := range got {
		if ev.Seq <= 2 {
			t.Fatalf("Since returned stale seq %d", ev.Seq)
		}
	}
	limited := s.Since(0, 2)
	if len(limited) != 2 || limited[0].Seq != 4 {
		t.Fatalf("limit behavior wrong: %+v", limited)
	}
}

func TestLookupMissing(t *testing.T) {
	s, _ := Open(t.TempDir(), 4)
	defer s.Close()
	if _, err := s.Lookup("nope"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
