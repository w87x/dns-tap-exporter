// Package collector exposes the tally window as Prometheus gauges. There are
// deliberately no counters: every value describes the last Window, so a
// restart never produces counter resets and history lives in Prometheus.
package collector

import (
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/w87x/dns-tap-exporter/internal/capture"
	"github.com/w87x/dns-tap-exporter/internal/tally"
)

type Config struct {
	Shards     []*tally.Shard
	Clock      *capture.Clock
	Slots      int
	SlotSecs   int64
	SampleRate uint32
	TopN       int
	MinCount   uint64 // minimum estimated count for a top entry
}

type Collector struct {
	c       Config
	started time.Time

	qps, rps, failRatio, malformed, drops, window, keysDropped *prometheus.Desc
	qtype, rcode                                               *prometheus.Desc
	topPair, topClient, topDomain                              *prometheus.Desc
	failPair, failClient, failDomain                           *prometheus.Desc
}

func New(c Config) *Collector {
	d := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc("dns_tap_"+name, help, labels, nil)
	}
	return &Collector{
		c: c, started: time.Now(),
		qps:         d("queries_per_second", "Queries/s seen on port 53 over the window (exact)."),
		rps:         d("responses_per_second", "Responses/s seen on port 53 over the window (exact)."),
		failRatio:   d("failure_ratio", "Share of responses with rcode != NOERROR over the window (exact)."),
		qtype:       d("queries_by_type_per_second", "Queries/s by qtype over the window (exact).", "qtype"),
		rcode:       d("responses_by_rcode_per_second", "Responses/s by rcode over the window (exact).", "rcode"),
		malformed:   d("malformed_per_second", "Port-53 packets/s that failed to parse as DNS."),
		drops:       d("capture_drops_per_second", "Packets/s dropped by the kernel before capture; non-zero means undercounting."),
		window:      d("window_seconds", "Effective averaging window (shorter than configured right after start)."),
		keysDropped: d("tracking_overflow_per_second", "Heavy-hitter entries/s ignored because a bucket hit its key limit."),
		topPair:     d("top_pair_queries_per_second", "Estimated queries/s of the top (client, domain) pairs.", "rank", "client", "domain"),
		topClient:   d("top_client_queries_per_second", "Estimated queries/s of the top clients.", "rank", "client"),
		topDomain:   d("top_domain_queries_per_second", "Estimated queries/s of the top domains.", "rank", "domain"),
		failPair:    d("top_pair_failures_per_second", "Estimated failing responses/s of the top (client, domain, rcode).", "rank", "client", "domain", "rcode"),
		failClient:  d("top_client_failures_per_second", "Estimated failing responses/s of the top (client, rcode).", "rank", "client", "rcode"),
		failDomain:  d("top_domain_failures_per_second", "Estimated failing responses/s of the top (domain, rcode).", "rank", "domain", "rcode"),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.qps, c.rps, c.failRatio, c.qtype, c.rcode, c.malformed, c.drops,
		c.window, c.keysDropped, c.topPair, c.topClient, c.topDomain, c.failPair, c.failClient, c.failDomain} {
		ch <- d
	}
}

func rcodeName(r int16) string {
	if s, ok := dns.RcodeToString[int(r)]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func qtypeName(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// Entry is one ranked heavy hitter. Unused fields are empty.
type Entry struct {
	Client string  `json:"client,omitempty"`
	Domain string  `json:"domain,omitempty"`
	Rcode  string  `json:"rcode,omitempty"`
	QPS    float64 `json:"qps"` // estimated queries (or failing responses) per second
}

// View is everything derived from one window, shared by /metrics and the UI.
type View struct {
	Time      time.Time          `json:"t"`
	WindowSec float64            `json:"window_sec"`
	QPS       float64            `json:"qps"`
	RPS       float64            `json:"rps"`
	FailRatio float64            `json:"fail_ratio"`
	Malformed float64            `json:"malformed"`
	Drops     float64            `json:"drops"`
	Overflow  float64            `json:"overflow"`
	ByType    map[string]float64 `json:"by_type"`
	ByRcode   map[string]float64 `json:"by_rcode"`

	TopPairs    []Entry `json:"top_pairs"`
	TopClients  []Entry `json:"top_clients"`
	TopDomains  []Entry `json:"top_domains"`
	FailPairs   []Entry `json:"fail_pairs"`
	FailClients []Entry `json:"fail_clients"`
	FailDomains []Entry `json:"fail_domains"`
}

// View computes the current window.
func (c *Collector) View() View {
	cur := c.c.Clock.Slot()
	snap := tally.Merge(c.c.Shards, cur)

	win := float64(int64(c.c.Slots) * c.c.SlotSecs)
	if since := time.Since(c.started).Seconds(); since < win {
		win = since
	}
	if win < 1 {
		win = 1
	}
	per := func(n uint64) float64 { return float64(n) / win }

	v := View{
		Time: time.Now().UTC(), WindowSec: win,
		QPS: per(snap.Queries), RPS: per(snap.Responses), Malformed: per(snap.Malformed),
		Drops: per(snap.CaptureDrops), Overflow: per(snap.KeysDropped),
		ByType: map[string]float64{}, ByRcode: map[string]float64{},
	}
	for t, n := range snap.QTypes {
		v.ByType[qtypeName(t)] = per(n)
	}
	var failed uint64
	for r, n := range snap.Rcodes {
		v.ByRcode[rcodeName(int16(r))] = per(n)
		if r != 0 {
			failed += n
		}
	}
	if snap.Responses > 0 {
		v.FailRatio = float64(failed) / float64(snap.Responses)
	}

	sr := uint64(max(c.c.SampleRate, 1))
	scale := float64(sr) / win // sampled count -> events/s
	min := (c.c.MinCount + sr - 1) / sr
	isQuery := func(k tally.Key) bool { return k.Rcode < 0 }
	isFail := func(k tally.Key) bool { return k.Rcode > 0 }
	list := func(m map[tally.Key]uint64, f func(tally.Key) bool, mk func(tally.Key) Entry) []Entry {
		es := tally.Top(m, c.c.TopN, min, f)
		out := make([]Entry, 0, len(es))
		for _, e := range es {
			x := mk(e.Key)
			x.QPS = float64(e.Count) * scale
			out = append(out, x)
		}
		return out
	}
	v.TopPairs = list(snap.Pairs, isQuery, func(k tally.Key) Entry { return Entry{Client: k.Client.String(), Domain: k.Domain} })
	v.TopClients = list(snap.Clients, isQuery, func(k tally.Key) Entry { return Entry{Client: k.Client.String()} })
	v.TopDomains = list(snap.Domains, isQuery, func(k tally.Key) Entry { return Entry{Domain: k.Domain} })
	v.FailPairs = list(snap.Pairs, isFail, func(k tally.Key) Entry {
		return Entry{Client: k.Client.String(), Domain: k.Domain, Rcode: rcodeName(k.Rcode)}
	})
	v.FailClients = list(snap.Clients, isFail, func(k tally.Key) Entry { return Entry{Client: k.Client.String(), Rcode: rcodeName(k.Rcode)} })
	v.FailDomains = list(snap.Domains, isFail, func(k tally.Key) Entry { return Entry{Domain: k.Domain, Rcode: rcodeName(k.Rcode)} })
	return v
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	v := c.View()
	g := func(d *prometheus.Desc, val float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, val, lv...)
	}
	g(c.window, v.WindowSec)
	g(c.qps, v.QPS)
	g(c.rps, v.RPS)
	g(c.malformed, v.Malformed)
	g(c.drops, v.Drops)
	g(c.keysDropped, v.Overflow)
	for t, x := range v.ByType {
		g(c.qtype, x, t)
	}
	for r, x := range v.ByRcode {
		g(c.rcode, x, r)
	}
	if v.RPS > 0 {
		g(c.failRatio, v.FailRatio)
	}
	rank := func(i int) string { return strconv.Itoa(i + 1) }
	for i, e := range v.TopPairs {
		g(c.topPair, e.QPS, rank(i), e.Client, e.Domain)
	}
	for i, e := range v.TopClients {
		g(c.topClient, e.QPS, rank(i), e.Client)
	}
	for i, e := range v.TopDomains {
		g(c.topDomain, e.QPS, rank(i), e.Domain)
	}
	for i, e := range v.FailPairs {
		g(c.failPair, e.QPS, rank(i), e.Client, e.Domain, e.Rcode)
	}
	for i, e := range v.FailClients {
		g(c.failClient, e.QPS, rank(i), e.Client, e.Rcode)
	}
	for i, e := range v.FailDomains {
		g(c.failDomain, e.QPS, rank(i), e.Domain, e.Rcode)
	}
}
