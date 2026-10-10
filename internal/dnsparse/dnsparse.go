// Package dnsparse extracts the few fields the exporter needs from a DNS
// payload without decoding the whole message and without per-packet allocs
// beyond the returned name string.
package dnsparse

// Msg is the header summary plus the first question of a DNS message.
type Msg struct {
	Response bool
	Opcode   uint8
	Rcode    uint8
	AA, TC   bool
	QType    uint16
	QName    string // lower-case, no trailing dot, "." for the root
}

const maxName = 255

// Parse reads the header and first question of a DNS payload. ok is false
// for anything malformed or without a question.
func Parse(p []byte) (m Msg, ok bool) {
	if len(p) < 12 {
		return m, false
	}
	m.Response = p[2]&0x80 != 0
	m.Opcode = (p[2] >> 3) & 0x0F
	m.AA = p[2]&0x04 != 0
	m.TC = p[2]&0x02 != 0
	m.Rcode = p[3] & 0x0F
	if p[4] == 0 && p[5] == 0 { // QDCOUNT
		return m, false
	}

	var buf [maxName]byte
	n, i := 0, 12
	for {
		if i >= len(p) {
			return m, false
		}
		l := int(p[i])
		if l == 0 {
			i++
			break
		}
		// Compression pointers cannot appear in the first question of a
		// well-formed message; treat them as garbage.
		if l&0xC0 != 0 || i+1+l > len(p) || n+l+1 > maxName {
			return m, false
		}
		for _, c := range p[i+1 : i+1+l] {
			switch {
			case c >= 'A' && c <= 'Z':
				c += 'a' - 'A'
			case c < 0x21 || c > 0x7e || c == '"' || c == '\\':
				c = '?' // keep label values printable and escape-free
			}
			buf[n] = c
			n++
		}
		buf[n] = '.'
		n++
		i += 1 + l
	}
	if i+4 > len(p) {
		return m, false
	}
	m.QType = uint16(p[i])<<8 | uint16(p[i+1])
	if n == 0 {
		m.QName = "."
	} else {
		m.QName = string(buf[:n-1])
	}
	return m, true
}
