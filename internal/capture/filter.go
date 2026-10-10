// Package capture taps an interface (or replays a pcap) and feeds DNS
// messages seen on port 53 into tally shards.
package capture

import "golang.org/x/net/bpf"

// Filter returns a classic BPF program accepting UDP/53 over Ethernet
// (IPv4 non-fragmented, IPv6 without extension headers) in either direction.
// 802.1Q/802.1ad frames are accepted wholesale and filtered in userspace.
func Filter() []bpf.Instruction {
	const (
		accept = 20
		reject = 21
	)
	skip := func(from, to int) uint8 { return uint8(to - from - 1) }
	return []bpf.Instruction{
		/* 0 */ bpf.LoadAbsolute{Off: 12, Size: 2},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: skip(1, 12)},
		/* 2 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: skip(2, 18)},
		// IPv4
		/* 3 */ bpf.LoadAbsolute{Off: 23, Size: 1},
		/* 4 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: skip(4, reject)},
		/* 5 */ bpf.LoadAbsolute{Off: 20, Size: 2},
		/* 6 */ bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: skip(6, reject)},
		/* 7 */ bpf.LoadMemShift{Off: 14},
		/* 8 */ bpf.LoadIndirect{Off: 14, Size: 2},
		/* 9 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: skip(9, accept)},
		/* 10 */ bpf.LoadIndirect{Off: 16, Size: 2},
		/* 11 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: skip(11, accept), SkipFalse: skip(11, reject)},
		// IPv6
		/* 12 */ bpf.LoadAbsolute{Off: 20, Size: 1},
		/* 13 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: skip(13, reject)},
		/* 14 */ bpf.LoadAbsolute{Off: 54, Size: 2},
		/* 15 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: skip(15, accept)},
		/* 16 */ bpf.LoadAbsolute{Off: 56, Size: 2},
		/* 17 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: skip(17, accept), SkipFalse: skip(17, reject)},
		// VLAN tags: let userspace sort it out
		/* 18 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8100, SkipTrue: skip(18, accept)},
		/* 19 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x88a8, SkipTrue: skip(19, accept), SkipFalse: skip(19, reject)},
		/* 20 */ bpf.RetConstant{Val: 262144},
		/* 21 */ bpf.RetConstant{Val: 0},
	}
}
