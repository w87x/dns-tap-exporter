// dns-tap-exporter passively taps port 53 on an interface and exposes
// per-window query/failure rates and top (client, domain) pairs as
// Prometheus gauges. It never binds port 53 and sits outside the DNS path.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/w87x/dns-tap-exporter/internal/capture"
	"github.com/w87x/dns-tap-exporter/internal/collector"
	"github.com/w87x/dns-tap-exporter/internal/history"
	"github.com/w87x/dns-tap-exporter/internal/tally"
	"github.com/w87x/dns-tap-exporter/internal/ui"
)

func main() {
	var (
		iface    = flag.String("iface", "", "interface to tap (e.g. eth0, vhost0)")
		pcapFile = flag.String("pcap", "", "replay a pcap file instead of live capture")
		listen   = flag.String("listen", ":9120", "metrics listen address")
		workers  = flag.Int("workers", 1, "AF_PACKET fanout workers")
		ringMB   = flag.Int("ring-mb", 64, "kernel ring size per worker, MiB")
		window   = flag.Duration("window", time.Minute, "averaging window")
		slot     = flag.Duration("slot", 5*time.Second, "bucket length")
		topN     = flag.Int("top", 5, "entries per top-N metric")
		minCount = flag.Uint64("min-count", 10, "minimum estimated hits in the window for a top entry")
		sample   = flag.Uint("sample", 1, "track 1 in N messages for top-N (totals stay exact)")
		maxKeys  = flag.Int("max-keys", 200000, "max tracked entries per bucket per table")
		collapse = flag.Bool("collapse", true, "fold names to registered domain (eTLD+1)")
		uiOn     = flag.Bool("ui", true, "serve the built-in dashboard at /ui (exposes client IPs and domains)")
		keep     = flag.Duration("history", 24*time.Hour, "how much history the dashboard keeps in memory")
		interval = flag.Duration("history-interval", time.Minute, "dashboard sample interval")
	)
	flag.Parse()
	if *iface == "" && *pcapFile == "" {
		log.Fatal("set --iface or --pcap")
	}
	if *slot < time.Second || *window < *slot {
		log.Fatal("need slot >= 1s and window >= slot")
	}

	slotSecs := int64(*slot / time.Second)
	slots := int(*window / *slot)
	cfg := tally.Config{Slots: slots, SlotSecs: slotSecs, MaxKeys: *maxKeys, SampleRate: uint32(*sample)}
	n := max(*workers, 1)
	if *pcapFile != "" {
		n = 1
	}
	shards := make([]*tally.Shard, n)
	for i := range shards {
		shards[i] = tally.NewShard(cfg, uint32(i+1)*2654435761)
	}
	clock := capture.NewClock(slotSecs)
	defer clock.Stop()

	col := collector.New(collector.Config{
		Shards: shards, Clock: clock, Slots: slots, SlotSecs: slotSecs,
		SampleRate: uint32(*sample), TopN: *topN, MinCount: *minCount,
	})
	reg := prometheus.NewRegistry()
	reg.MustRegister(col)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *uiOn {
		rec := history.New(*keep, *interval)
		ui.Register(mux, rec, col.View, *keep)
		go rec.Run(ctx, col.View)
	}

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	if *pcapFile != "" {
		pk, err := capture.ReplayPcap(*pcapFile, capture.NewHandler(shards[0], clock, *collapse))
		if err != nil {
			log.Fatalf("replay: %v", err)
		}
		log.Printf("replayed %d packets; serving metrics on %s (Ctrl-C to exit)", pk, *listen)
		<-ctx.Done()
	} else {
		log.Printf("tapping %s (%d workers), metrics on %s", *iface, n, *listen)
		err := capture.RunLive(ctx, capture.Options{Iface: *iface, Workers: n, RingMB: *ringMB}, shards, clock, *collapse)
		if err != nil {
			log.Fatalf("capture: %v", err)
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}
