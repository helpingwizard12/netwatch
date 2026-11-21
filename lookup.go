package main

// Offline lookups: well-known ports and a small table of who owns big IP
// ranges. Nothing here contacts the network.

import (
	"net/netip"
	"strings"
	"sync"
)

var services = map[int]string{
	20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
	80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 143: "IMAP",
	161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE (VPN)", 514: "Syslog",
	548: "AFP", 587: "SMTP", 631: "IPP (printing)", 853: "DNS-over-TLS", 993: "IMAPS", 995: "POP3S",
	1194: "OpenVPN", 1900: "SSDP", 3000: "Dev server", 3306: "MySQL", 3478: "STUN", 3722: "Apple DeviceLink",
	4070: "Spotify", 4500: "IPsec NAT-T", 5000: "AirPlay/Dev", 5222: "XMPP", 5223: "Apple Push", 5228: "Google Push",
	5353: "mDNS (Bonjour)", 5355: "LLMNR", 5432: "PostgreSQL", 6379: "Redis", 7000: "AirPlay", 7233: "Temporal",
	8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9090: "Prometheus", 9100: "node_exporter",
	19302: "Google STUN", 27017: "MongoDB", 51820: "WireGuard", 57621: "Spotify Connect", 62078: "iPhone sync",
}

func serviceFor(proto string, lport, rport int, quic bool) string {
	if quic {
		return "QUIC / HTTP/3"
	}
	if s, ok := services[rport]; ok {
		return s
	}
	if s, ok := services[lport]; ok {
		return s
	}
	return ""
}

// Approximate owners of large address blocks. Good enough to answer
// "who is this?" at a glance; it is not a full WHOIS database.
var ownerTable = []struct{ cidr, org string }{
	{"160.79.104.0/23", "Anthropic"}, {"2607:6bc0::/48", "Anthropic"},
	{"104.16.0.0/13", "Cloudflare"}, {"104.24.0.0/14", "Cloudflare"}, {"172.64.0.0/13", "Cloudflare"},
	{"162.158.0.0/15", "Cloudflare"}, {"188.114.96.0/20", "Cloudflare"}, {"1.1.1.0/24", "Cloudflare DNS"},
	{"1.0.0.0/24", "Cloudflare DNS"}, {"2606:4700::/32", "Cloudflare"}, {"2a06:98c0::/29", "Cloudflare"},
	{"8.8.8.0/24", "Google DNS"}, {"8.8.4.0/24", "Google DNS"}, {"142.250.0.0/15", "Google"},
	{"172.217.0.0/16", "Google"}, {"216.58.192.0/19", "Google"}, {"74.125.0.0/16", "Google"},
	{"209.85.128.0/17", "Google"}, {"64.233.160.0/19", "Google"}, {"108.177.0.0/17", "Google"},
	{"34.0.0.0/8", "Google Cloud"}, {"35.184.0.0/13", "Google Cloud"}, {"104.154.0.0/15", "Google Cloud"},
	{"2001:4860::/32", "Google"}, {"2404:6800::/32", "Google"}, {"2607:f8b0::/32", "Google"},
	{"2a00:1450::/32", "Google"}, {"2600:1900::/28", "Google Cloud"},
	{"151.101.0.0/16", "Fastly CDN"}, {"199.232.0.0/16", "Fastly CDN"}, {"146.75.0.0/16", "Fastly CDN"},
	{"2a04:4e40::/29", "Fastly CDN"},
	{"23.0.0.0/12", "Akamai CDN"}, {"104.64.0.0/10", "Akamai CDN"}, {"184.24.0.0/13", "Akamai CDN"},
	{"2600:1400::/24", "Akamai CDN"}, {"2a02:26f0::/29", "Akamai CDN"},
	{"17.0.0.0/8", "Apple"}, {"2620:149::/32", "Apple"}, {"2403:300::/32", "Apple"}, {"2a01:b740::/29", "Apple"},
	{"3.0.0.0/9", "Amazon AWS"}, {"13.32.0.0/12", "Amazon AWS / CloudFront"}, {"18.128.0.0/9", "Amazon AWS"},
	{"52.0.0.0/10", "Amazon AWS"}, {"54.64.0.0/10", "Amazon AWS"}, {"54.128.0.0/10", "Amazon AWS"},
	{"99.84.0.0/16", "Amazon CloudFront"}, {"2600:1f00::/24", "Amazon AWS"}, {"2600:9000::/28", "Amazon CloudFront"},
	{"13.64.0.0/11", "Microsoft Azure"}, {"20.0.0.0/8", "Microsoft"}, {"40.64.0.0/10", "Microsoft"},
	{"52.96.0.0/12", "Microsoft 365"}, {"2603:1000::/24", "Microsoft"}, {"2620:1ec::/36", "Microsoft"},
	{"157.240.0.0/16", "Meta"}, {"31.13.24.0/21", "Meta"}, {"2a03:2880::/32", "Meta"},
	{"140.82.112.0/20", "GitHub"}, {"185.199.108.0/22", "GitHub"}, {"192.30.252.0/22", "GitHub"},
	{"35.186.224.0/20", "Spotify (GCP)"},
	{"185.125.188.0/22", "Canonical (Ubuntu)"},
	{"100.64.0.0/10", "Carrier-grade NAT / Tailscale"},
}

type ownerEntry struct {
	p   netip.Prefix
	org string
}

var (
	owners     []ownerEntry
	ownerCache sync.Map
)

func init() {
	for _, o := range ownerTable {
		if p, err := netip.ParsePrefix(o.cidr); err == nil {
			owners = append(owners, ownerEntry{p, o.org})
		}
	}
}

func ownerOf(ip string) string {
	if v, ok := ownerCache.Load(ip); ok {
		return v.(string)
	}
	res := computeOwner(ip)
	ownerCache.Store(ip, res)
	return res
}

func computeOwner(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap().WithZone("")
	switch {
	case a.IsLoopback():
		return "This Mac (loopback)"
	case a.String() == "255.255.255.255":
		return "Broadcast (everyone on the network)"
	case a.String() == "224.0.0.251" || a.String() == "ff02::fb":
		return "mDNS multicast (Bonjour)"
	case a.String() == "239.255.255.250" || strings.HasPrefix(a.String(), "ff02::c"):
		return "SSDP multicast (UPnP)"
	case a.IsMulticast():
		return "Multicast"
	case a.IsLinkLocalUnicast():
		return "Local link (same Wi-Fi/cable)"
	case a.IsPrivate():
		return "Local network"
	case a.IsUnspecified():
		return "Unspecified"
	}
	best := -1
	org := ""
	for _, o := range owners {
		if o.p.Contains(a) && o.p.Bits() > best {
			best, org = o.p.Bits(), o.org
		}
	}
	return org
}

func isLocalScope(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.String() == "255.255.255.255"
}
