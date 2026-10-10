//go:build !linux

package capture

import (
	"context"
	"errors"

	"github.com/w87x/dns-tap-exporter/internal/tally"
)

type Options struct {
	Iface   string
	Workers int
	RingMB  int
}

func RunLive(context.Context, Options, []*tally.Shard, *Clock, bool) error {
	return errors.New("live capture needs Linux AF_PACKET; use --pcap for offline replay")
}
