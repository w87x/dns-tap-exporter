package dnsparse

import "testing"

func question(name string, flags2, flags3 byte, qtype uint16) []byte {
	p := []byte{0x12, 0x34, flags2, flags3, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range splitLabels(name) {
		p = append(p, byte(len(l)))
		p = append(p, l...)
	}
	return append(p, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func splitLabels(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '.' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestQuery(t *testing.T) {
	m, ok := Parse(question("WWW.Example.COM", 0x01, 0, 28))
	if !ok || m.Response || m.QName != "www.example.com" || m.QType != 28 {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}

func TestNXDomainResponse(t *testing.T) {
	m, ok := Parse(question("nope.example.com", 0x81, 0x83, 1))
	if !ok || !m.Response || m.Rcode != 3 {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}

func TestFlags(t *testing.T) {
	m, ok := Parse(question("a.b", 0x86, 0, 1)) // QR|AA|TC
	if !ok || !m.Response || !m.AA || !m.TC {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}

func TestRoot(t *testing.T) {
	m, ok := Parse(question("", 0, 0, 2))
	if !ok || m.QName != "." {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}

func TestMalformed(t *testing.T) {
	good := question("example.com", 0, 0, 1)
	for name, p := range map[string][]byte{
		"short":       good[:8],
		"noquestion":  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"truncname":   good[:16],
		"notype":      good[:len(good)-3],
		"compression": append(append([]byte{}, good[:12]...), 0xC0, 0x0C, 0, 1, 0, 1),
	} {
		if _, ok := Parse(p); ok {
			t.Errorf("%s: expected failure", name)
		}
	}
}

func TestUnprintableLabelBytes(t *testing.T) {
	p := question("ab", 0, 0, 1)
	p[13] = 0x01 // inside the first label
	m, ok := Parse(p)
	if !ok || m.QName != "?b" {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}
