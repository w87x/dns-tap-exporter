package capture

import (
	"errors"
	"io"
	"os"

	"github.com/google/gopacket/pcapgo"
)

// ReplayPcap feeds every packet of a classic pcap file to h (pure Go, no
// privileges needed). Useful for tests and offline analysis.
func ReplayPcap(path string, h *Handler) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		data, _, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		h.Packet(data)
		n++
	}
}
