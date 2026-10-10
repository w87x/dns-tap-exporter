package capture

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/afpacket"
	"golang.org/x/net/bpf"

	"github.com/w87x/dns-tap-exporter/internal/tally"
)

// Options for a live AF_PACKET capture.
type Options struct {
	Iface   string
	Workers int // sockets in one fanout group; flows are hashed across them
	RingMB  int // per worker
}

// RunLive taps the interface until ctx is cancelled. shards[i] belongs to
// worker i. Requires CAP_NET_RAW.
func RunLive(ctx context.Context, o Options, shards []*tally.Shard, clock *Clock, collapse bool) error {
	raw, err := bpf.Assemble(Filter())
	if err != nil {
		return err
	}
	const frame = 4096
	blocks := o.RingMB * 1024 * 1024 / (frame * 128)
	if blocks < 1 {
		blocks = 1
	}
	fanoutID := uint16(time.Now().UnixNano() & 0xffff)

	taps := make([]*afpacket.TPacket, len(shards))
	for i := range shards {
		t, err := afpacket.NewTPacket(
			afpacket.OptInterface(o.Iface),
			afpacket.OptFrameSize(frame),
			afpacket.OptBlockSize(frame*128),
			afpacket.OptNumBlocks(blocks),
			afpacket.OptPollTimeout(500*time.Millisecond),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3,
		)
		if err != nil {
			return fmt.Errorf("open %s: %w", o.Iface, err)
		}
		if err := t.SetBPF(raw); err != nil {
			return fmt.Errorf("attach filter: %w", err)
		}
		if len(shards) > 1 {
			if err := t.SetFanout(afpacket.FanoutHash, fanoutID); err != nil {
				return fmt.Errorf("fanout: %w", err)
			}
		}
		_ = t.InitSocketStats()
		taps[i] = t
	}

	errc := make(chan error, len(taps))
	for i, t := range taps {
		go func(t *afpacket.TPacket, sh *tally.Shard) { errc <- worker(ctx, t, sh, clock, collapse) }(t, shards[i])
	}
	var first error
	for range taps {
		if err := <-errc; err != nil && first == nil {
			first = err
		}
	}
	for _, t := range taps {
		t.Close()
	}
	return first
}

func worker(ctx context.Context, t *afpacket.TPacket, sh *tally.Shard, clock *Clock, collapse bool) error {
	h := NewHandler(sh, clock, collapse)
	var lastDrops uint
	nextStats := time.Now()
	for ctx.Err() == nil {
		data, _, err := t.ZeroCopyReadPacketData()
		if err != nil && !errors.Is(err, afpacket.ErrTimeout) {
			return err
		}
		if err == nil {
			h.Packet(data)
		}
		if now := time.Now(); now.After(nextStats) {
			nextStats = now.Add(time.Second)
			if _, v3, err := t.SocketStats(); err == nil { // cumulative
				if d := v3.Drops(); d >= lastDrops {
					if d > lastDrops {
						sh.Drops(clock.Slot(), uint64(d-lastDrops))
					}
					lastDrops = d
				}
			} else {
				log.Printf("socket stats: %v", err)
			}
		}
	}
	return nil
}
