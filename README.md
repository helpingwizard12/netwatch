# Netwatch

A local, browser-based view of every packet entering and leaving your Mac —
grouped by app, connection, remote host and DNS lookup.

Pure Go, no dependencies. It runs the built-in `tcpdump` for capture, decodes
the packets itself, and serves the interface on `127.0.0.1` only. Nothing is
sent anywhere.

## What it shows

- **Apps** – live download/upload rate per app, totals, packets, active connections, PIDs
- **Connections** – app ⇄ remote host name and approximate owner (Google, Cloudflare,
  Apple…), service (HTTPS, QUIC, DNS…), TLS version, bytes each way, state, who opened it
- **Remote hosts** – every server contacted, with apps, ports and traffic
- **DNS lookups** – every name looked up and the IPs returned
- **Packets** – time, direction, app, protocol, source/destination, size, summary;
  click one for every decoded field and a hex dump

Decoded where the protocol is unencrypted: DNS/mDNS, TLS server name (SNI), ALPN,
TLS version/cipher, QUIC headers, plain HTTP, DHCP, NTP, SSDP, ARP, ICMP/ICMPv6.
App names come from the macOS kernel's per-packet metadata (Apple pcapng / PKTAP),
with `lsof` as a fallback.

Contents of HTTPS, QUIC and VPN traffic are encrypted and are not visible.

## Install & run (macOS)

Requires Go 1.27+.

    go install github.com/helpingwizard12/netwatch@latest
    netwatch

or from a clone:

    go build -o netwatch . && ./netwatch

It asks for your password once (for `sudo tcpdump`) and opens
http://127.0.0.1:8765. Ctrl+C stops it.

## Options

    -include-loopback       also show traffic between programs on this Mac (can be noisy)
    -filter 'not port 443'  extra tcpdump filter
    -save capture.pcap      also save raw packets (open later in Wireshark)
    -read capture.pcap      replay a saved capture instead of capturing live
    -i en0                  capture one interface instead of all
    -port 8766              different UI port
    -no-browser             don't open the browser

## Code

| File | Purpose |
|---|---|
| `main.go` | flags, `sudo tcpdump` process, local web server |
| `pcap.go` | pcap / pcapng stream reader, incl. Apple process-info blocks |
| `decode.go` | PKTAP, Ethernet, IPv4/6, TCP/UDP/ICMP/ARP, DNS, TLS, QUIC, HTTP, DHCP… |
| `state.go` | connections, apps, hosts, DNS log, traffic series |
| `lookup.go` | port names and approximate IP-range owners (offline) |
| `sysinfo.go` | this Mac's addresses, full process names, `lsof` fallback |
| `web/index.html` | the interface (embedded into the binary) |
