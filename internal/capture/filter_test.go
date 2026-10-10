package capture

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

func frame(t *testing.T, v6 bool, vlan bool, src, dst uint16, tcp bool) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{1, 2, 3, 4, 5, 6}, DstMAC: []byte{6, 5, 4, 3, 2, 1}}
	var ls []gopacket.SerializableLayer
	var net gopacket.NetworkLayer
	if v6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 8, SrcIP: []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, DstIP: []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}
		ip.NextHeader = layers.IPProtocolUDP
		net = ip
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 8, SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, Protocol: layers.IPProtocolUDP}
		net = ip
	}
	if tcp {
		switch ip := net.(type) {
		case *layers.IPv4:
			ip.Protocol = layers.IPProtocolTCP
		case *layers.IPv6:
			ip.NextHeader = layers.IPProtocolTCP
		}
	}
	var l4 gopacket.SerializableLayer
	if tcp {
		x := &layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst)}
		x.SetNetworkLayerForChecksum(net)
		l4 = x
	} else {
		x := &layers.UDP{SrcPort: layers.UDPPort(src), DstPort: layers.UDPPort(dst)}
		x.SetNetworkLayerForChecksum(net)
		l4 = x
	}
	ls = append(ls, eth)
	if vlan {
		eth.EthernetType = layers.EthernetTypeDot1Q
		ls = append(ls, &layers.Dot1Q{VLANIdentifier: 5, Type: layers.EthernetTypeIPv4})
	}
	ls = append(ls, net.(gopacket.SerializableLayer), l4, gopacket.Payload(make([]byte, 20)))
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFilter(t *testing.T) {
	vm, err := bpf.NewVM(Filter())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"v4 query", frame(t, false, false, 40000, 53, false), true},
		{"v4 response", frame(t, false, false, 53, 40000, false), true},
		{"v6 query", frame(t, true, false, 40000, 53, false), true},
		{"v6 response", frame(t, true, false, 53, 40000, false), true},
		{"v4 other port", frame(t, false, false, 40000, 80, false), false},
		{"v6 other port", frame(t, true, false, 1234, 5678, false), false},
		{"v4 tcp/53", frame(t, false, false, 40000, 53, true), false},
		{"vlan passes to userspace", frame(t, false, true, 40000, 80, false), true},
	}
	for _, c := range cases {
		n, err := vm.Run(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (n > 0) != c.want {
			t.Errorf("%s: accepted=%v want %v", c.name, n > 0, c.want)
		}
	}
}
