package tally

import (
	"net/netip"
	"testing"
)

func cfg() Config { return Config{Slots: 3, SlotSecs: 5, MaxKeys: 100, SampleRate: 1} }

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestWindowExpiry(t *testing.T) {
	s := NewShard(cfg(), 1)
	s.Add(10, Query, ip("10.0.0.1"), "a.com", 1, 0)
	s.Add(11, Query, ip("10.0.0.1"), "a.com", 1, 0)
	if got := Merge([]*Shard{s}, 12).Queries; got != 2 {
		t.Fatalf("slots 10,11 live at 12: got %d", got)
	}
	if got := Merge([]*Shard{s}, 13).Queries; got != 1 { // slot 10 aged out
		t.Fatalf("slot 10 expired at 13: got %d", got)
	}
}

func TestLazyReset(t *testing.T) {
	s := NewShard(cfg(), 1)
	s.Add(10, Query, ip("10.0.0.1"), "a.com", 1, 0)
	s.Add(13, Query, ip("10.0.0.2"), "b.com", 1, 0) // same ring index as 10
	snap := Merge([]*Shard{s}, 13)
	if snap.Queries != 1 || len(snap.Pairs) != 1 {
		t.Fatalf("stale bucket not reset: %+v", snap)
	}
}

func TestResponsesAndTop(t *testing.T) {
	s1, s2 := NewShard(cfg(), 1), NewShard(cfg(), 2)
	for i := 0; i < 5; i++ {
		s1.Add(1, Response, ip("10.0.0.9"), "bad.com", 1, 3)
	}
	for i := 0; i < 2; i++ {
		s2.Add(1, Response, ip("10.0.0.8"), "ok.com", 1, 0)
		s2.Add(1, Response, ip("10.0.0.7"), "bad.com", 1, 3)
	}
	snap := Merge([]*Shard{s1, s2}, 1)
	if snap.Rcodes[3] != 7 || snap.Rcodes[0] != 2 {
		t.Fatalf("rcodes: %v", snap.Rcodes)
	}
	top := Top(snap.Pairs, 5, 1, func(k Key) bool { return k.Rcode > 0 })
	if len(top) != 2 || top[0].Count != 5 || top[0].Key.Client != ip("10.0.0.9") {
		t.Fatalf("top: %+v", top)
	}
	doms := Top(snap.Domains, 1, 1, func(k Key) bool { return k.Rcode == 3 })
	if doms[0].Key.Domain != "bad.com" || doms[0].Count != 7 {
		t.Fatalf("domains: %+v", doms)
	}
}

func TestMaxKeysBound(t *testing.T) {
	c := cfg()
	c.MaxKeys = 2
	s := NewShard(c, 1)
	for _, d := range []string{"a", "b", "c", "d"} {
		s.Add(1, Query, ip("10.0.0.1"), d, 1, 0)
	}
	snap := Merge([]*Shard{s}, 1)
	if len(snap.Pairs) != 2 || snap.KeysDropped == 0 || snap.Queries != 4 {
		t.Fatalf("bound not enforced / exact counters affected: %+v", snap)
	}
}

func TestSampling(t *testing.T) {
	c := cfg()
	c.SampleRate = 10
	s := NewShard(c, 12345)
	for i := 0; i < 100000; i++ {
		s.Add(1, Query, ip("10.0.0.1"), "a.com", 1, 0)
	}
	snap := Merge([]*Shard{s}, 1)
	est := snap.Pairs[Key{ip("10.0.0.1"), "a.com", -1}] * 10
	if snap.Queries != 100000 || est < 90000 || est > 110000 {
		t.Fatalf("exact=%d sampled estimate=%d", snap.Queries, est)
	}
}
