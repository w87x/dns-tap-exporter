# AF_PACKET support in gopacket uses cgo, so build with gcc and run on a glibc base.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/dns-tap-exporter .

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/dns-tap-exporter /usr/local/bin/dns-tap-exporter
# Runs as root *inside* the container because a non-root user does not get
# CAP_NET_RAW as an effective capability. Confine it with:
#   docker run --network host --cap-drop ALL --cap-add NET_RAW --read-only ...
USER 0
EXPOSE 9120
ENTRYPOINT ["/usr/local/bin/dns-tap-exporter"]
CMD ["--iface=eth0", "--listen=:9120"]
