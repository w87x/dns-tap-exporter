package history

import (
	"testing"
	"time"

	"github.com/w87x/dns-tap-exporter/internal/collector"
)

func TestRingOrderAndCutoff(t *testing.T) {
	r := New(3*time.Minute, time.Minute) // 3 slots
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ { // overflow the ring
		r.Add(collector.View{Time: base.Add(time.Duration(i) * time.Minute), QPS: float64(i)})
	}
	got := r.Since(base)
	if len(got) != 3 || got[0].QPS != 2 || got[2].QPS != 4 {
		t.Fatalf("want oldest-first [2 3 4], got %+v", got)
	}
	if got := r.Since(base.Add(150 * time.Second)); len(got) != 2 || got[0].QPS != 3 {
		t.Fatalf("cutoff: %+v", got)
	}
}
