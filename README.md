# dns-tap-exporter

Passive DNS tap + Prometheus exporter for a busy resolver (built for the
`named` that ships with OpenSDN / Tungsten Fabric). It sniffs port 53 on an
interface, so it is **not in the DNS path**, never binds port 53, and needs no
change to named. It answers, during a traffic spike:

* **who** is asking (client IP), **for what** (domain), and **how many** (q/s),
* what is **failing** (NXDOMAIN, SERVFAIL, REFUSED…) and for whom,
* overall query / response rates by qtype and rcode.

Millions of queries stay cheap: totals are exact; the heavy-hitter tables use
bounded memory, optional sampling, and fold names to the registered domain
(`x123.nx.evil.test` → `evil.test`) so random-subdomain floods cannot blow up
cardinality.

## Metrics

Everything is a **gauge over the last window** (default 1m): there are no
counters, so a restart never produces counter resets and Prometheus holds the
history. Scrape every 1m.

| metric | meaning |
|---|---|
| `dns_tap_queries_per_second`, `dns_tap_responses_per_second` | exact rates |
| `dns_tap_failure_ratio` | share of responses with rcode ≠ NOERROR |
| `dns_tap_queries_by_type_per_second{qtype}` | exact |
| `dns_tap_responses_by_rcode_per_second{rcode}` | exact |
| `dns_tap_top_pair_queries_per_second{rank,client,domain}` | top client→domain pairs (estimate) |
| `dns_tap_top_client_queries_per_second{rank,client}` / `..._top_domain_...{rank,domain}` | top clients / domains |
| `dns_tap_top_pair_failures_per_second{rank,client,domain,rcode}` (+ `_client_`, `_domain_` variants) | top failing responses |
| `dns_tap_capture_drops_per_second` | kernel dropped packets: **non-zero means undercounting** |
| `dns_tap_malformed_per_second`, `dns_tap_tracking_overflow_per_second`, `dns_tap_window_seconds` | health |

`rank` (1..N) is the stable label; `client`/`domain` change as the leaders do,
so only N series per metric exist at once.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: dns-tap
    scrape_interval: 1m
    static_configs: [{targets: ['control-1:9120', 'control-2:9120']}]
```

```yaml
# alerts
- alert: DnsFailureSpike
  expr: dns_tap_failure_ratio > 0.3 and dns_tap_queries_per_second > 100
  for: 2m
- alert: DnsTapDroppingPackets
  expr: dns_tap_capture_drops_per_second > 0
```

## Built-in dashboard (no Prometheus needed)

`http://HOST:9120/ui/` is a small dependency-free SPA that polls the exporter
every 60 s (`?refresh=30` to change). The exporter keeps 24 h of one-minute
samples in memory (`--history`, `--history-interval`). Click a point on any
chart to see *who → what* for that minute; **Latest** follows live.

* History is in memory: it resets on restart. Prometheus is the durable store.
* The UI and `/api/*` expose client IPs and domains and have **no
  authentication**. Bind to loopback / a management network, firewall it, or
  disable it with `--ui=false`.

## Run

```
dns-tap-exporter --iface eth0                # needs CAP_NET_RAW
dns-tap-exporter --pcap sample.pcap          # offline replay, no privileges
```

Key flags: `--workers` (AF_PACKET fanout sockets), `--window`, `--slot`,
`--top`, `--min-count`, `--sample N` (track 1 in N messages for the top-N
tables; totals stay exact and top-N rates are scaled back up), `--collapse`,
`--ui`. See `--help`.

### Docker (host networking, as named runs)

Yes, it works in a container next to a host-networked named. The tap needs to
share the network namespace of the interface it watches, and only `NET_RAW`:

```
docker run -d --name dns-tap --restart unless-stopped \
  --network host --cap-drop ALL --cap-add NET_RAW \
  --read-only --security-opt no-new-privileges \
  ghcr.io/w87x/dns-tap-exporter:main --iface=eth0 --listen=:9120
```

The image is built with cgo (AF_PACKET via gopacket) on a glibc base.

### Kayobe

`deploy/kayobe/dns-tap-exporter.yml` runs the container with the settings
above:

```
kayobe playbook run etc/kayobe/ansible/dns-tap-exporter.yml \
  -e dns_tap_hosts=<group> -e dns_tap_iface=eth0 -e dns_tap_image=<registry>/dns-tap-exporter:<tag>
```

## Caveats

* **VM identity.** On a control node, named sees the vRouter agent's / compute
  node's address as the client, not the VM. To see individual VMs, run the tap
  on the compute node (e.g. `vhost0`). Queries the agent answers itself never
  reach named and are only visible there.
* **UDP only.** DNS over TCP is not captured. IPv6 with extension headers and
  IP fragments are skipped by the kernel filter.
* **Loopback** shows every packet twice, so `--iface lo` double-counts. Real
  NICs do not.
* Top-N values are estimates when `--sample > 1` or when a bucket reaches
  `--max-keys` (`dns_tap_tracking_overflow_per_second` shows that). Totals,
  qtype and rcode rates are exact.

## Development

```
go vet ./... && go test -race ./...
```

CI (`.github/workflows/ci.yml`) runs gofmt, vet, race tests and a UI syntax
check, then builds the image and pushes it to GHCR on `main` and `v*` tags.
