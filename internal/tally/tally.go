// Package tally keeps sliding-window, bounded-memory counts of DNS traffic.
//
// Time is divided into fixed-length slots. A shard keeps a ring of buckets,
// one per slot; a bucket is lazily reset when its slot comes around again, so
// no rotation goroutine is needed. Everything is exposed as per-window
// values (no monotonic counters), so a restart just starts a fresh window.
package tally

import (
	"net/netip"
	"sort"
	"sync"
)

// Kind of event being tallied.
type Kind uint8

const (
	Query    Kind = iota // client = source address
	Response             // client = destination address
)

// Key identifies a heavy-hitter entry. Rcode is -1 for queries.
type Key struct {
	Client netip.Addr
	Domain string // empty for per-client entries
	Rcode  int16
}

// Config bounds memory and defines the window.
type Config struct {
	Slots      int // buckets in the ring
	SlotSecs   int64
	MaxKeys    int // per map, per bucket
	SampleRate uint32
}

type bucket struct {
	slot       int64
	qtypes     map[uint16]uint64 // exact
	rcodes     map[uint8]uint64  // exact, responses
	queries    uint64
	responses  uint64
	malformed  uint64
	drops      uint64         // kernel-reported capture drops
	pairs      map[Key]uint64 // sampled (client, domain, rcode)
	clients    map[Key]uint64 // sampled (client, rcode), Domain == ""
	domains    map[Key]uint64 // sampled (domain, rcode), zero Client
	keysDroped uint64
}

func newBucket() bucket {
	return bucket{
		qtypes:  map[uint16]uint64{},
		rcodes:  map[uint8]uint64{},
		pairs:   map[Key]uint64{},
		clients: map[Key]uint64{},
		domains: map[Key]uint64{},
	}
}

func (b *bucket) reset(slot int64) {
	b.slot = slot
	clear(b.qtypes)
	clear(b.rcodes)
	clear(b.pairs)
	clear(b.clients)
	clear(b.domains)
	b.queries, b.responses, b.malformed, b.drops, b.keysDroped = 0, 0, 0, 0, 0
}

// Shard is owned by one capture worker; the mutex is only contended by scrapes.
type Shard struct {
	cfg  Config
	mu   sync.Mutex
	ring []bucket
	rng  uint32
}

func NewShard(cfg Config, seed uint32) *Shard {
	s := &Shard{cfg: cfg, ring: make([]bucket, cfg.Slots), rng: seed | 1}
	for i := range s.ring {
		s.ring[i] = newBucket()
		s.ring[i].slot = -1
	}
	return s
}

func (s *Shard) bucketFor(slot int64) *bucket {
	b := &s.ring[int(slot%int64(s.cfg.Slots))]
	if b.slot != slot {
		b.reset(slot)
	}
	return b
}

func (s *Shard) sampled() bool {
	if s.cfg.SampleRate <= 1 {
		return true
	}
	s.rng ^= s.rng << 13 // xorshift32
	s.rng ^= s.rng >> 17
	s.rng ^= s.rng << 5
	return s.rng%s.cfg.SampleRate == 0
}

func bump(m map[Key]uint64, k Key, max int, dropped *uint64) {
	if _, ok := m[k]; ok || len(m) < max {
		m[k]++
		return
	}
	*dropped++
}

// Add records one DNS message. rcode is ignored for queries.
func (s *Shard) Add(slot int64, kind Kind, client netip.Addr, domain string, qtype uint16, rcode uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucketFor(slot)
	rc := int16(-1)
	if kind == Query {
		b.queries++
		b.qtypes[qtype]++
	} else {
		b.responses++
		b.rcodes[rcode]++
		rc = int16(rcode)
	}
	if !s.sampled() {
		return
	}
	bump(b.pairs, Key{client, domain, rc}, s.cfg.MaxKeys, &b.keysDroped)
	bump(b.clients, Key{Client: client, Rcode: rc}, s.cfg.MaxKeys, &b.keysDroped)
	bump(b.domains, Key{Domain: domain, Rcode: rc}, s.cfg.MaxKeys, &b.keysDroped)
}

// Drops records packets the kernel dropped before we could read them.
func (s *Shard) Drops(slot int64, n uint64) {
	s.mu.Lock()
	s.bucketFor(slot).drops += n
	s.mu.Unlock()
}

// Malformed records a packet on port 53 that did not parse as DNS.
func (s *Shard) Malformed(slot int64) {
	s.mu.Lock()
	s.bucketFor(slot).malformed++
	s.mu.Unlock()
}

// Snapshot is the merged view of the live window across shards.
type Snapshot struct {
	Queries, Responses, Malformed, CaptureDrops, KeysDropped uint64
	QTypes                                                   map[uint16]uint64
	Rcodes                                                   map[uint8]uint64
	Pairs, Clients, Domains                                  map[Key]uint64 // sampled counts
}

// Merge combines shards over slots (cur-Slots, cur].
func Merge(shards []*Shard, cur int64) Snapshot {
	out := Snapshot{
		QTypes: map[uint16]uint64{}, Rcodes: map[uint8]uint64{},
		Pairs: map[Key]uint64{}, Clients: map[Key]uint64{}, Domains: map[Key]uint64{},
	}
	for _, s := range shards {
		s.mu.Lock()
		for i := range s.ring {
			b := &s.ring[i]
			if b.slot < 0 || b.slot > cur || b.slot <= cur-int64(s.cfg.Slots) {
				continue
			}
			out.Queries += b.queries
			out.Responses += b.responses
			out.Malformed += b.malformed
			out.CaptureDrops += b.drops
			out.KeysDropped += b.keysDroped
			for k, v := range b.qtypes {
				out.QTypes[k] += v
			}
			for k, v := range b.rcodes {
				out.Rcodes[k] += v
			}
			for k, v := range b.pairs {
				out.Pairs[k] += v
			}
			for k, v := range b.clients {
				out.Clients[k] += v
			}
			for k, v := range b.domains {
				out.Domains[k] += v
			}
		}
		s.mu.Unlock()
	}
	return out
}

// Entry is one ranked heavy hitter.
type Entry struct {
	Key   Key
	Count uint64
}

// Top returns the n largest entries of m passing filter, count >= min,
// ordered by count then key for stable output.
func Top(m map[Key]uint64, n int, min uint64, filter func(Key) bool) []Entry {
	var es []Entry
	for k, v := range m {
		if v >= min && filter(k) {
			es = append(es, Entry{k, v})
		}
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].Count != es[j].Count {
			return es[i].Count > es[j].Count
		}
		a, b := es[i].Key, es[j].Key
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		return a.Client.Less(b.Client)
	})
	if len(es) > n {
		es = es[:n]
	}
	return es
}
