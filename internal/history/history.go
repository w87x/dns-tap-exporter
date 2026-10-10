// Package history keeps a rolling in-memory series of window views so the UI
// can draw graphs without Prometheus. It is lost on restart by design;
// Prometheus is the durable store.
package history

import (
	"context"
	"sync"
	"time"

	"github.com/w87x/dns-tap-exporter/internal/collector"
)

type Recorder struct {
	mu       sync.Mutex
	ring     []collector.View
	next     int
	full     bool
	Interval time.Duration
}

func New(keep, interval time.Duration) *Recorder {
	n := int(keep / interval)
	if n < 1 {
		n = 1
	}
	return &Recorder{ring: make([]collector.View, n), Interval: interval}
}

func (r *Recorder) Add(v collector.View) {
	r.mu.Lock()
	r.ring[r.next] = v
	r.next = (r.next + 1) % len(r.ring)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

// Run samples fn every Interval until ctx ends.
func (r *Recorder) Run(ctx context.Context, fn func() collector.View) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.Add(fn())
		case <-ctx.Done():
			return
		}
	}
}

// Since returns samples newer than the cutoff, oldest first.
func (r *Recorder) Since(cutoff time.Time) []collector.View {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []collector.View
	if r.full {
		all = append(all, r.ring[r.next:]...)
	}
	all = append(all, r.ring[:r.next]...)
	out := all[:0:0]
	for _, v := range all {
		if v.Time.After(cutoff) {
			out = append(out, v)
		}
	}
	return out
}
