package capture

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/w87x/dns-tap-exporter/internal/tally"
)

func dnsFrame(t *testing.T, src, dst string, sport, dport uint16, response bool, rcode byte, name string) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{1, 2, 3, 4, 5, 6}, DstMAC: []byte{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 8, Protocol: layers.IPProtocolUDP,
		SrcIP: netip.MustParseAddr(src).AsSlice(), DstIP: netip.MustParseAddr(dst).AsSlice()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	udp.SetNetworkLayerForChecksum(ip)
	flags := byte(0x01)
	if response {
		flags |= 0x80
	}
	p := []byte{0, 1, flags, rcode, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"www", name, "com"} {
		p = append(p, byte(len(l)))
		p = append(p, l...)
	}
	p = append(p, 0, 0, 1, 0, 1)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		eth, ip, udp, gopacket.Payload(p)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestHandlerDirectionAndCollapse(t *testing.T) {
	sh := tally.NewShard(tally.Config{Slots: 2, SlotSecs: 5, MaxKeys: 100, SampleRate: 1}, 1)
	clock := NewClock(5)
	defer clock.Stop()
	h := NewHandler(sh, clock, true)

	h.Packet(dnsFrame(t, "10.1.1.1", "10.0.0.53", 40000, 53, false, 0, "Foo"))   // query
	h.Packet(dnsFrame(t, "10.0.0.53", "10.1.1.1", 53, 40000, true, 3, "Foo"))    // NXDOMAIN reply to the same client
	h.Packet(dnsFrame(t, "10.1.1.1", "10.0.0.99", 40000, 5353, false, 0, "Foo")) // not port 53: ignored
	h.Packet([]byte{1, 2, 3})                                                    // garbage frame

	snap := tally.Merge([]*tally.Shard{sh}, clock.Slot())
	if snap.Queries != 1 || snap.Responses != 1 || snap.Rcodes[3] != 1 {
		t.Fatalf("totals: %+v", snap)
	}
	client := netip.MustParseAddr("10.1.1.1")
	if snap.Pairs[tally.Key{Client: client, Domain: "foo.com", Rcode: -1}] != 1 {
		t.Fatalf("query pair missing / not collapsed to eTLD+1: %v", snap.Pairs)
	}
	if snap.Pairs[tally.Key{Client: client, Domain: "foo.com", Rcode: 3}] != 1 {
		t.Fatalf("response must be attributed to the destination (client): %v", snap.Pairs)
	}
}
