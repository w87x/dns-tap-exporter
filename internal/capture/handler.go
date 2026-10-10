package capture

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/publicsuffix"

	"github.com/w87x/dns-tap-exporter/internal/dnsparse"
	"github.com/w87x/dns-tap-exporter/internal/tally"
)

// Clock publishes the current slot number; updating an atomic a few times a
// second is far cheaper than calling time.Now per packet.
type Clock struct {
	secs int64
	slot atomic.Int64
	stop chan struct{}
}

func NewClock(slotSecs int64) *Clock {
	c := &Clock{secs: slotSecs, stop: make(chan struct{})}
	c.slot.Store(time.Now().Unix() / slotSecs)
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case now := <-t.C:
				c.slot.Store(now.Unix() / slotSecs)
			case <-c.stop:
				return
			}
		}
	}()
	return c
}

func (c *Clock) Slot() int64 { return c.slot.Load() }
func (c *Clock) Stop()       { close(c.stop) }

// Handler decodes link-layer frames and feeds DNS messages into one shard.
// It is not safe for concurrent use; create one per worker.
type Handler struct {
	shard    *tally.Shard
	clock    *Clock
	collapse bool

	parser *gopacket.DecodingLayerParser
	eth    layers.Ethernet
	dot1q  layers.Dot1Q
	ip4    layers.IPv4
	ip6    layers.IPv6
	udp    layers.UDP
	decode []gopacket.LayerType
}

// NewHandler returns a handler. collapse folds query names to their
// registered domain (eTLD+1) so random-subdomain floods stay bounded.
func NewHandler(shard *tally.Shard, clock *Clock, collapse bool) *Handler {
	h := &Handler{shard: shard, clock: clock, collapse: collapse}
	h.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &h.eth, &h.dot1q, &h.ip4, &h.ip6, &h.udp)
	h.parser.IgnoreUnsupported = true
	return h
}

func (h *Handler) Packet(data []byte) {
	if err := h.parser.DecodeLayers(data, &h.decode); err != nil && len(h.decode) == 0 {
		return
	}
	var haveUDP, v4, v6 bool
	for _, t := range h.decode {
		switch t {
		case layers.LayerTypeIPv4:
			v4 = true
		case layers.LayerTypeIPv6:
			v6 = true
		case layers.LayerTypeUDP:
			haveUDP = true
		}
	}
	if !haveUDP || !(v4 || v6) {
		return
	}
	toServer, fromServer := h.udp.DstPort == 53, h.udp.SrcPort == 53
	if !toServer && !fromServer {
		return
	}
	slot := h.clock.Slot()

	msg, ok := dnsparse.Parse(h.udp.Payload)
	if !ok {
		h.shard.Malformed(slot)
		return
	}
	if msg.Opcode != 0 {
		return
	}
	var srcB, dstB []byte
	if v4 {
		srcB, dstB = h.ip4.SrcIP, h.ip4.DstIP
	} else {
		srcB, dstB = h.ip6.SrcIP, h.ip6.DstIP
	}
	name := msg.QName
	if h.collapse {
		if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
			name = d
		}
	}
	switch {
	case !msg.Response && toServer:
		if a, ok := netip.AddrFromSlice(srcB); ok {
			h.shard.Add(slot, tally.Query, a.Unmap(), name, msg.QType, 0)
		}
	case msg.Response && fromServer:
		if a, ok := netip.AddrFromSlice(dstB); ok { // the client is the destination
			h.shard.Add(slot, tally.Response, a.Unmap(), name, msg.QType, msg.Rcode)
		}
	}
}
