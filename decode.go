package main

// Packet decoding: PKTAP (macOS per-packet process + direction metadata),
// link layer, IPv4/IPv6, TCP/UDP/ICMP/ARP and a handful of application
// protocols whose interesting bits travel unencrypted (DNS, TLS SNI, HTTP,
// QUIC headers, DHCP, NTP, SSDP).

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

type Packet struct {
	ID     int64       `json:"id"`
	T      float64     `json:"t"`
	Dir    string      `json:"dir"` // in | out | local
	Iface  string      `json:"iface"`
	App    string      `json:"app"`
	PID    int         `json:"pid"`
	EApp   string      `json:"eapp,omitempty"` // app the traffic is on behalf of
	Proto  string      `json:"proto"`
	Src    string      `json:"src"`
	Sport  int         `json:"sport"`
	Dst    string      `json:"dst"`
	Dport  int         `json:"dport"`
	Len    int         `json:"len"`
	Info   string      `json:"info"`
	Host   string      `json:"host,omitempty"`
	Layers []string    `json:"layers"`
	Fields [][2]string `json:"fields,omitempty"`
	Hex    string      `json:"hex,omitempty"`

	dirKnown   bool
	tcpFlags   uint8
	payload    []byte
	payLen     int
	head       []byte
	dns        *DNSMsg
	srcMAC     string
	l4ok       bool
	kernelMeta bool
	ePID       int
}

func (p *Packet) add(k, v string) {
	if v != "" {
		p.Fields = append(p.Fields, [2]string{k, v})
	}
}

const (
	finF = 0x01
	synF = 0x02
	rstF = 0x04
	pshF = 0x08
	ackF = 0x10
	urgF = 0x20
	eceF = 0x40
	cwrF = 0x80
)

func decodeFrame(f rawFrame) *Packet {
	p := &Packet{T: float64(f.ts.UnixNano()) / 1e9, Len: f.origLen, Iface: f.iface}
	data, link := f.data, f.link
	if link == 149 || link == 258 { // Apple PKTAP
		rest, dlt, ok := p.parsePktap(data, f.order)
		if !ok {
			p.Proto, p.Info = "?", "unreadable PKTAP header"
			return p
		}
		data, link = rest, dlt
		// PKTAP's own length covers the inner frame only
		if p.Len > len(f.data) || p.Len <= 0 {
			p.Len = len(data)
		} else {
			p.Len -= len(f.data) - len(data)
		}
	}
	if f.meta {
		if f.dir != "" {
			p.Dir, p.dirKnown = f.dir, true
		}
		if f.pid > 0 && f.comm != "" {
			p.PID, p.App, p.kernelMeta = f.pid, f.comm, true
		}
		if f.ecomm != "" && f.ecomm != f.comm {
			p.EApp, p.ePID = f.ecomm, f.epid
			if p.App == "" && f.epid > 0 {
				p.PID, p.App, p.kernelMeta = f.epid, f.ecomm, true
			}
		}
		p.add("Service class", svcName(f.svc))
	}
	p.add("Captured bytes", fmt.Sprint(len(data)))
	p.decodeLink(link, data, f.order)
	if p.Info == "" {
		p.Info = p.Proto
	}
	return p
}

func (p *Packet) parsePktap(d []byte, bo binary.ByteOrder) ([]byte, uint32, bool) {
	if len(d) < 108 {
		return nil, 0, false
	}
	hlen := int(bo.Uint32(d[0:]))
	if hlen < 108 || hlen > len(d) {
		return nil, 0, false
	}
	dlt := bo.Uint32(d[8:])
	p.Iface = cstr(d[12:36])
	flags := bo.Uint32(d[36:])
	switch {
	case flags&1 != 0:
		p.Dir, p.dirKnown = "in", true
	case flags&2 != 0:
		p.Dir, p.dirKnown = "out", true
	}
	pid := int(int32(bo.Uint32(d[52:])))
	comm := cstr(d[56:73])
	epid := int(int32(bo.Uint32(d[84:])))
	ecomm := cstr(d[88:105])
	if pid > 0 && comm != "" {
		p.PID, p.App, p.kernelMeta = pid, comm, true
	}
	if ecomm != "" && ecomm != comm {
		p.EApp, p.ePID = ecomm, epid
	}
	if p.App == "" && epid > 0 && ecomm != "" {
		p.PID, p.App, p.kernelMeta = epid, ecomm, true
	}
	svc := bo.Uint32(d[76:])
	p.add("Service class", svcName(svc))
	p.Layers = append(p.Layers, "PKTAP")
	return d[hlen:], dlt, true
}

func svcName(s uint32) string {
	switch s {
	case 0:
		return ""
	case 100:
		return "BK_SYS (background system)"
	case 200:
		return "BK (background)"
	case 300:
		return "BE (best effort)"
	case 400:
		return "RD (responsive data)"
	case 500:
		return "OAM (operations)"
	case 600:
		return "AV (multimedia streaming)"
	case 700:
		return "RV (responsive multimedia)"
	case 800:
		return "VI (interactive video)"
	case 900:
		return "VO (interactive voice)"
	case 1000:
		return "CTL (network control)"
	}
	return fmt.Sprint(s)
}

func mac(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func (p *Packet) decodeLink(link uint32, d []byte, bo binary.ByteOrder) {
	switch link {
	case 1: // Ethernet
		if len(d) < 14 {
			p.Proto = "Ethernet"
			return
		}
		p.Layers = append(p.Layers, "Ethernet")
		p.srcMAC = mac(d[6:12])
		p.add("Source MAC", p.srcMAC)
		p.add("Destination MAC", mac(d[0:6]))
		et := binary.BigEndian.Uint16(d[12:])
		off := 14
		for (et == 0x8100 || et == 0x88a8) && len(d) >= off+4 {
			p.add("VLAN", fmt.Sprint(binary.BigEndian.Uint16(d[off:])&0x0fff))
			et = binary.BigEndian.Uint16(d[off+2:])
			off += 4
		}
		p.decodeEther(et, d[off:])
	case 0, 108: // BSD loopback / utun: 4-byte address family
		if len(d) < 4 {
			return
		}
		fam := bo.Uint32(d)
		if link == 108 {
			fam = binary.BigEndian.Uint32(d)
		}
		p.Layers = append(p.Layers, "Null/Loopback")
		switch fam {
		case 2:
			p.decodeIPv4(d[4:])
		case 24, 28, 30:
			p.decodeIPv6(d[4:])
		default:
			p.decodeRawIP(d[4:])
		}
	case 12, 14, 101, 228, 229: // raw IP
		p.decodeRawIP(d)
	case 113: // Linux cooked v1
		if len(d) < 16 {
			return
		}
		p.Layers = append(p.Layers, "Linux SLL")
		p.sllDir(binary.BigEndian.Uint16(d[0:]))
		p.decodeEther(binary.BigEndian.Uint16(d[14:]), d[16:])
	case 276: // Linux cooked v2
		if len(d) < 20 {
			return
		}
		p.Layers = append(p.Layers, "Linux SLL2")
		p.sllDir(uint16(d[10]))
		p.decodeEther(binary.BigEndian.Uint16(d[0:]), d[20:])
	default:
		p.Proto = fmt.Sprintf("link %d", link)
	}
}

func (p *Packet) sllDir(t uint16) {
	if p.dirKnown {
		return
	}
	switch t {
	case 4:
		p.Dir, p.dirKnown = "out", true
	case 0, 1, 2:
		p.Dir, p.dirKnown = "in", true
	}
}

func (p *Packet) decodeRawIP(d []byte) {
	if len(d) == 0 {
		return
	}
	switch d[0] >> 4 {
	case 4:
		p.decodeIPv4(d)
	case 6:
		p.decodeIPv6(d)
	}
}

func (p *Packet) decodeEther(et uint16, d []byte) {
	switch et {
	case 0x0800:
		p.decodeIPv4(d)
	case 0x86dd:
		p.decodeIPv6(d)
	case 0x0806:
		p.decodeARP(d)
	case 0x888e:
		p.Proto, p.Info = "EAPOL", "Wi-Fi authentication (802.1X/WPA handshake)"
	case 0x88cc:
		p.Proto, p.Info = "LLDP", "Link-layer discovery"
	default:
		p.Proto = fmt.Sprintf("EtherType 0x%04x", et)
	}
}

func (p *Packet) decodeARP(d []byte) {
	p.Proto = "ARP"
	p.Layers = append(p.Layers, "ARP")
	if len(d) < 28 {
		return
	}
	op := binary.BigEndian.Uint16(d[6:])
	smac := mac(d[8:14])
	sip := netip.AddrFrom4([4]byte(d[14:18])).String()
	tip := netip.AddrFrom4([4]byte(d[24:28])).String()
	p.Src, p.Dst = sip, tip
	p.add("Sender MAC", smac)
	p.add("Sender IP", sip)
	p.add("Target IP", tip)
	if op == 1 {
		p.Info = fmt.Sprintf("Who has %s? Tell %s", tip, sip)
	} else {
		p.Info = fmt.Sprintf("%s is at %s", sip, smac)
	}
}

func (p *Packet) decodeIPv4(d []byte) {
	if len(d) < 20 || d[0]>>4 != 4 {
		p.Proto = "IPv4?"
		return
	}
	ihl := int(d[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(d[2:]))
	if ihl < 20 || ihl > len(d) {
		return
	}
	p.Layers = append(p.Layers, "IPv4")
	p.Src = netip.AddrFrom4([4]byte(d[12:16])).String()
	p.Dst = netip.AddrFrom4([4]byte(d[16:20])).String()
	frag := binary.BigEndian.Uint16(d[6:])
	p.add("IP version", "4")
	p.add("TTL", fmt.Sprint(d[8]))
	p.add("IP ID", fmt.Sprint(binary.BigEndian.Uint16(d[4:])))
	if frag&0x4000 != 0 {
		p.add("Don't fragment", "yes")
	}
	if ecn := d[1] & 3; ecn != 0 {
		p.add("ECN", fmt.Sprint(ecn))
	}
	if dscp := d[1] >> 2; dscp != 0 {
		p.add("DSCP", fmt.Sprint(dscp))
	}
	end := total
	if end > len(d) || end < ihl {
		end = len(d)
	}
	l4len := total - ihl
	if frag&0x1fff != 0 {
		p.Proto = ipProtoName(d[9])
		p.Info = "IP fragment"
		return
	}
	p.decodeL4(d[9], d[ihl:end], l4len)
}

func (p *Packet) decodeIPv6(d []byte) {
	if len(d) < 40 {
		p.Proto = "IPv6?"
		return
	}
	p.Layers = append(p.Layers, "IPv6")
	p.Src = netip.AddrFrom16([16]byte(d[8:24])).Unmap().String()
	p.Dst = netip.AddrFrom16([16]byte(d[24:40])).Unmap().String()
	plen := int(binary.BigEndian.Uint16(d[4:]))
	nh := d[6]
	p.add("IP version", "6")
	p.add("Hop limit", fmt.Sprint(d[7]))
	if fl := binary.BigEndian.Uint32(d[0:]) & 0xfffff; fl != 0 {
		p.add("Flow label", fmt.Sprintf("0x%05x", fl))
	}
	off := 40
	for i := 0; i < 8; i++ {
		switch nh {
		case 0, 43, 60:
			if len(d) < off+2 {
				return
			}
			hl := (int(d[off+1]) + 1) * 8
			nh = d[off]
			off += hl
			plen -= hl
		case 44:
			if len(d) < off+8 {
				return
			}
			if binary.BigEndian.Uint16(d[off+2:])&0xfff8 != 0 {
				p.Proto, p.Info = ipProtoName(d[off]), "IPv6 fragment"
				return
			}
			nh = d[off]
			off += 8
			plen -= 8
		default:
			i = 8
		}
	}
	if off > len(d) {
		return
	}
	end := 40 + int(binary.BigEndian.Uint16(d[4:]))
	if end > len(d) || end < off {
		end = len(d)
	}
	p.decodeL4(nh, d[off:end], plen)
}

func ipProtoName(n byte) string {
	switch n {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6-in-IPv4"
	case 47:
		return "GRE"
	case 50:
		return "ESP (IPsec)"
	case 51:
		return "AH (IPsec)"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	}
	return fmt.Sprintf("IP proto %d", n)
}

func (p *Packet) setHead(b []byte) {
	n := len(b)
	if n > 256 {
		n = 256
	}
	p.head = append([]byte(nil), b[:n]...)
}

func (p *Packet) decodeL4(proto byte, d []byte, l4len int) {
	p.Proto = ipProtoName(proto)
	switch proto {
	case 6:
		if len(d) < 20 {
			return
		}
		p.Layers = append(p.Layers, "TCP")
		p.l4ok = true
		p.Sport = int(binary.BigEndian.Uint16(d[0:]))
		p.Dport = int(binary.BigEndian.Uint16(d[2:]))
		off := int(d[12]>>4) * 4
		p.tcpFlags = d[13]
		p.add("TCP flags", tcpFlagStr(p.tcpFlags))
		p.add("Sequence #", fmt.Sprint(binary.BigEndian.Uint32(d[4:])))
		if p.tcpFlags&ackF != 0 {
			p.add("Ack #", fmt.Sprint(binary.BigEndian.Uint32(d[8:])))
		}
		p.add("Window", fmt.Sprint(binary.BigEndian.Uint16(d[14:])))
		if off < 20 || off > len(d) {
			off = len(d)
		}
		p.parseTCPOpts(d[20:off])
		p.payload = d[off:]
		p.payLen = l4len - off
		if p.payLen < 0 {
			p.payLen = len(p.payload)
		}
		p.add("Payload bytes", fmt.Sprint(p.payLen))
		p.setHead(p.payload)
		p.Info = tcpSummary(p.tcpFlags, p.payLen)
		p.decodeTCPApp()
	case 17:
		if len(d) < 8 {
			return
		}
		p.Layers = append(p.Layers, "UDP")
		p.l4ok = true
		p.Sport = int(binary.BigEndian.Uint16(d[0:]))
		p.Dport = int(binary.BigEndian.Uint16(d[2:]))
		p.payload = d[8:]
		p.payLen = int(binary.BigEndian.Uint16(d[4:])) - 8
		if p.payLen < 0 {
			p.payLen = len(p.payload)
		}
		p.add("Payload bytes", fmt.Sprint(p.payLen))
		p.setHead(p.payload)
		p.Info = fmt.Sprintf("%d bytes", p.payLen)
		p.decodeUDPApp()
	case 1, 58:
		p.Layers = append(p.Layers, p.Proto)
		p.l4ok = true
		if len(d) >= 2 {
			p.Info = icmpName(proto == 58, d[0], d[1])
			p.add("ICMP type/code", fmt.Sprintf("%d / %d", d[0], d[1]))
		}
		p.setHead(d)
	case 2:
		p.Layers = append(p.Layers, "IGMP")
		p.Info = "Multicast group membership"
	default:
		p.setHead(d)
	}
}

func (p *Packet) parseTCPOpts(o []byte) {
	var parts []string
	for len(o) > 0 {
		k := o[0]
		if k == 0 {
			break
		}
		if k == 1 {
			o = o[1:]
			continue
		}
		if len(o) < 2 || int(o[1]) < 2 || int(o[1]) > len(o) {
			break
		}
		v := o[2:o[1]]
		switch k {
		case 2:
			if len(v) == 2 {
				parts = append(parts, fmt.Sprintf("MSS %d", binary.BigEndian.Uint16(v)))
			}
		case 3:
			if len(v) == 1 {
				parts = append(parts, fmt.Sprintf("window scale %d", v[0]))
			}
		case 4:
			parts = append(parts, "SACK permitted")
		case 8:
			parts = append(parts, "timestamps")
		}
		o = o[o[1]:]
	}
	p.add("TCP options", strings.Join(parts, ", "))
}

func tcpFlagStr(f uint8) string {
	var s []string
	names := []struct {
		b uint8
		n string
	}{{synF, "SYN"}, {finF, "FIN"}, {rstF, "RST"}, {pshF, "PSH"}, {ackF, "ACK"}, {urgF, "URG"}, {eceF, "ECE"}, {cwrF, "CWR"}}
	for _, x := range names {
		if f&x.b != 0 {
			s = append(s, x.n)
		}
	}
	return strings.Join(s, ", ")
}

func tcpSummary(f uint8, n int) string {
	switch {
	case f&rstF != 0:
		return "RST · connection reset"
	case f&synF != 0 && f&ackF != 0:
		return "SYN-ACK · connection accepted"
	case f&synF != 0:
		return "SYN · opening connection"
	case f&finF != 0:
		return "FIN · closing connection"
	case n > 0:
		return fmt.Sprintf("Data · %d bytes", n)
	}
	return "ACK"
}

func icmpName(v6 bool, t, c byte) string {
	if v6 {
		switch t {
		case 1:
			return "Destination unreachable"
		case 2:
			return "Packet too big"
		case 3:
			return "Time exceeded"
		case 128:
			return "Echo (ping) request"
		case 129:
			return "Echo (ping) reply"
		case 133:
			return "Router solicitation"
		case 134:
			return "Router advertisement"
		case 135:
			return "Neighbor solicitation (who has this address?)"
		case 136:
			return "Neighbor advertisement"
		case 143:
			return "Multicast listener report"
		}
		return fmt.Sprintf("ICMPv6 type %d", t)
	}
	switch t {
	case 0:
		return "Echo (ping) reply"
	case 3:
		return fmt.Sprintf("Destination unreachable (code %d)", c)
	case 5:
		return "Redirect"
	case 8:
		return "Echo (ping) request"
	case 11:
		return "Time exceeded (TTL)"
	}
	return fmt.Sprintf("ICMP type %d", t)
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}

func (p *Packet) decodeTCPApp() {
	b := p.payload
	if len(b) == 0 {
		return
	}
	for _, m := range httpMethods {
		if strings.HasPrefix(string(b[:min(len(b), 8)]), m) {
			p.decodeHTTP(b, true)
			return
		}
	}
	if len(b) >= 5 && string(b[:5]) == "HTTP/" {
		p.decodeHTTP(b, false)
		return
	}
	if (p.Sport == 53 || p.Dport == 53) && len(b) > 2 {
		if m := parseDNS(b[2:]); m != nil {
			p.dns = m
			p.Layers = append(p.Layers, "DNS")
			p.Info = m.summary()
			m.fields(p)
		}
	}
	// TLS records are inspected in state.go (they can span segments)
}

func (p *Packet) decodeHTTP(b []byte, req bool) {
	p.Layers = append(p.Layers, "HTTP")
	text := string(b)
	lines := strings.Split(text, "\r\n")
	p.Info = "HTTP " + lines[0]
	p.add("HTTP first line", lines[0])
	for _, l := range lines[1:] {
		if l == "" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			lk := strings.ToLower(k)
			if lk == "host" || lk == "user-agent" || lk == "content-type" || lk == "server" || lk == "content-length" {
				p.add("HTTP "+k, strings.TrimSpace(v))
			}
			if lk == "host" {
				p.Host = strings.TrimSpace(v)
			}
		}
	}
}

func (p *Packet) decodeUDPApp() {
	b := p.payload
	port := func(n int) bool { return p.Sport == n || p.Dport == n }
	switch {
	case port(53) || port(5353) || port(5355):
		if m := parseDNS(b); m != nil {
			p.dns = m
			name := "DNS"
			if port(5353) {
				name = "mDNS"
			} else if port(5355) {
				name = "LLMNR"
			}
			p.Layers = append(p.Layers, name)
			p.Info = name + " " + m.summary()
			m.fields(p)
		}
	case port(443) || port(80) || port(8443):
		p.decodeQUIC(b)
	case port(67) || port(68):
		p.decodeDHCP(b)
	case port(123):
		p.Layers = append(p.Layers, "NTP")
		if len(b) > 0 {
			mode := b[0] & 7
			p.Info = map[byte]string{3: "NTP time request", 4: "NTP time reply"}[mode]
			if p.Info == "" {
				p.Info = fmt.Sprintf("NTP (mode %d)", mode)
			}
		}
	case port(1900):
		p.Layers = append(p.Layers, "SSDP")
		first, _, _ := strings.Cut(string(b), "\r\n")
		p.Info = "SSDP " + first
		for _, l := range strings.Split(string(b), "\r\n") {
			if k, v, ok := strings.Cut(l, ":"); ok {
				switch strings.ToUpper(k) {
				case "ST", "NT", "SERVER", "LOCATION", "USN":
					p.add("SSDP "+strings.ToUpper(k), strings.TrimSpace(v))
				}
			}
		}
	case port(3478) || port(19302):
		p.Layers = append(p.Layers, "STUN")
		p.Info = "STUN (finding public address for calls/WebRTC)"
	case port(137):
		p.Layers = append(p.Layers, "NetBIOS")
		p.Info = "NetBIOS name service"
	case port(51820):
		p.Layers = append(p.Layers, "WireGuard")
		p.Info = "WireGuard VPN"
	}
}

func (p *Packet) decodeQUIC(b []byte) {
	if len(b) < 1 || b[0]&0x40 == 0 {
		return
	}
	p.Layers = append(p.Layers, "QUIC")
	if b[0]&0x80 == 0 {
		p.Info = fmt.Sprintf("QUIC data (encrypted) · %d bytes", p.payLen)
		return
	}
	if len(b) < 6 {
		return
	}
	ver := binary.BigEndian.Uint32(b[1:])
	t := (b[0] & 0x30) >> 4
	types := []string{"Initial", "0-RTT", "Handshake", "Retry"}
	vs := fmt.Sprintf("0x%08x", ver)
	switch ver {
	case 1:
		vs = "v1"
	case 0x6b3343cf:
		vs = "v2"
		types = []string{"Retry", "Initial", "0-RTT", "Handshake"}
	case 0:
		p.Info = "QUIC version negotiation"
		return
	}
	p.add("QUIC version", vs)
	p.add("QUIC packet type", types[t])
	p.Info = fmt.Sprintf("QUIC %s (%s) · %d bytes", types[t], vs, p.payLen)
	if len(b) > 6 {
		dl := int(b[5])
		if 6+dl <= len(b) {
			p.add("QUIC dest. connection ID", fmt.Sprintf("%x", b[6:6+dl]))
		}
	}
}

func (p *Packet) decodeDHCP(b []byte) {
	p.Layers = append(p.Layers, "DHCP")
	p.Info = "DHCP"
	if len(b) < 240 || binary.BigEndian.Uint32(b[236:]) != 0x63825363 {
		return
	}
	p.add("DHCP client MAC", mac(b[28:34]))
	if yi := netip.AddrFrom4([4]byte(b[16:20])); !yi.IsUnspecified() {
		p.add("DHCP offered IP", yi.String())
	}
	o := b[240:]
	for len(o) >= 2 && o[0] != 255 {
		if o[0] == 0 {
			o = o[1:]
			continue
		}
		l := int(o[1])
		if 2+l > len(o) {
			break
		}
		v := o[2 : 2+l]
		switch o[0] {
		case 53:
			if l == 1 {
				names := map[byte]string{1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
				p.Info = "DHCP " + names[v[0]]
			}
		case 12:
			p.add("DHCP hostname", string(v))
		case 6:
			var ds []string
			for i := 0; i+4 <= len(v); i += 4 {
				ds = append(ds, netip.AddrFrom4([4]byte(v[i:i+4])).String())
			}
			p.add("DHCP DNS servers", strings.Join(ds, ", "))
		case 3:
			if l >= 4 {
				p.add("DHCP router", netip.AddrFrom4([4]byte(v[0:4])).String())
			}
		}
		o = o[2+l:]
	}
}

// ---------- DNS ----------

type DNSQ struct {
	Name string
	Type uint16
}
type DNSRR struct {
	Name  string
	Type  uint16
	TTL   uint32
	Value string
}
type DNSMsg struct {
	Response  bool
	RCode     int
	Questions []DNSQ
	Answers   []DNSRR
}

var dnsTypes = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

func dnsType(t uint16) string {
	if s, ok := dnsTypes[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

var rcodes = map[int]string{0: "OK", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN (no such name)", 4: "NOTIMP", 5: "REFUSED"}

func readName(p []byte, off int) (string, int, bool) {
	var labels []string
	end, jumped := off, false
	for hops := 0; hops < 64; hops++ {
		if off >= len(p) {
			return "", 0, false
		}
		l := int(p[off])
		switch {
		case l == 0:
			if !jumped {
				end = off + 1
			}
			n := strings.Join(labels, ".")
			if n == "" {
				n = "."
			}
			return n, end, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(p) {
				return "", 0, false
			}
			if !jumped {
				end = off + 2
			}
			jumped = true
			off = (l&0x3f)<<8 | int(p[off+1])
		default:
			if off+1+l > len(p) {
				return "", 0, false
			}
			labels = append(labels, string(p[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, false
}

func parseDNS(p []byte) *DNSMsg {
	if len(p) < 12 {
		return nil
	}
	flags := binary.BigEndian.Uint16(p[2:])
	qd := int(binary.BigEndian.Uint16(p[4:]))
	an := int(binary.BigEndian.Uint16(p[6:]))
	ns := int(binary.BigEndian.Uint16(p[8:]))
	ar := int(binary.BigEndian.Uint16(p[10:]))
	if qd > 32 || an > 128 {
		return nil
	}
	m := &DNSMsg{Response: flags&0x8000 != 0, RCode: int(flags & 0xf)}
	off := 12
	for i := 0; i < qd; i++ {
		n, o, ok := readName(p, off)
		if !ok || o+4 > len(p) {
			return m
		}
		m.Questions = append(m.Questions, DNSQ{n, binary.BigEndian.Uint16(p[o:]) & 0x7fff})
		off = o + 4
	}
	total := an + ns + ar
	for i := 0; i < total && i < 128; i++ {
		n, o, ok := readName(p, off)
		if !ok || o+10 > len(p) {
			return m
		}
		t := binary.BigEndian.Uint16(p[o:])
		ttl := binary.BigEndian.Uint32(p[o+4:])
		rl := int(binary.BigEndian.Uint16(p[o+8:]))
		o += 10
		if o+rl > len(p) {
			return m
		}
		rd := p[o : o+rl]
		var v string
		switch {
		case t == 1 && rl == 4:
			v = netip.AddrFrom4([4]byte(rd)).String()
		case t == 28 && rl == 16:
			v = netip.AddrFrom16([16]byte(rd)).String()
		case t == 5 || t == 12 || t == 2:
			v, _, _ = readName(p, o)
		case t == 33 && rl > 6:
			tn, _, _ := readName(p, o+6)
			v = fmt.Sprintf("%s:%d", tn, binary.BigEndian.Uint16(rd[4:]))
		case t == 16:
			var parts []string
			for j := 0; j < len(rd); {
				l := int(rd[j])
				if j+1+l > len(rd) {
					break
				}
				parts = append(parts, string(rd[j+1:j+1+l]))
				j += 1 + l
			}
			v = strings.Join(parts, " ")
			if len(v) > 120 {
				v = v[:120] + "…"
			}
		case t == 41:
			off = o + rl
			continue // EDNS OPT pseudo-record
		default:
			v = fmt.Sprintf("%d bytes", rl)
		}
		if i < an || t == 1 || t == 28 {
			m.Answers = append(m.Answers, DNSRR{n, t, ttl, v})
		}
		off = o + rl
	}
	return m
}

func (m *DNSMsg) qname() (string, string) {
	if len(m.Questions) == 0 {
		if len(m.Answers) > 0 {
			return m.Answers[0].Name, dnsType(m.Answers[0].Type)
		}
		return "", ""
	}
	return m.Questions[0].Name, dnsType(m.Questions[0].Type)
}

func (m *DNSMsg) answerStr() string {
	var vs []string
	for _, a := range m.Answers {
		vs = append(vs, a.Value)
		if len(vs) == 6 {
			vs = append(vs, fmt.Sprintf("+%d more", len(m.Answers)-6))
			break
		}
	}
	return strings.Join(vs, ", ")
}

func (m *DNSMsg) summary() string {
	n, t := m.qname()
	if !m.Response {
		return fmt.Sprintf("query %s %s", t, n)
	}
	if m.RCode != 0 {
		return fmt.Sprintf("response %s %s → %s", t, n, rcodes[m.RCode])
	}
	a := m.answerStr()
	if a == "" {
		a = "(no records)"
	}
	return fmt.Sprintf("response %s %s → %s", t, n, a)
}

func (m *DNSMsg) fields(p *Packet) {
	for _, q := range m.Questions {
		p.add("DNS question", q.Name+" ("+dnsType(q.Type)+")")
	}
	for _, a := range m.Answers {
		p.add("DNS answer", fmt.Sprintf("%s %s %s (ttl %ds)", a.Name, dnsType(a.Type), a.Value, a.TTL))
	}
	if m.Response {
		p.add("DNS result", rcodes[m.RCode])
	}
}

// ---------- TLS ----------

type tlsHello struct {
	sni      string
	alpn     []string
	versions []string
	cipher   string
}

type rd struct {
	b   []byte
	i   int
	bad bool
}

func (r *rd) need(n int) bool {
	if r.bad || r.i+n > len(r.b) {
		r.bad = true
		return false
	}
	return true
}
func (r *rd) u8() int {
	if !r.need(1) {
		return 0
	}
	r.i++
	return int(r.b[r.i-1])
}
func (r *rd) u16() int {
	if !r.need(2) {
		return 0
	}
	r.i += 2
	return int(binary.BigEndian.Uint16(r.b[r.i-2:]))
}
func (r *rd) skip(n int) {
	if r.need(n) {
		r.i += n
	}
}
func (r *rd) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	r.i += n
	return r.b[r.i-n : r.i]
}

func tlsVersion(v int) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	}
	if v&0x0f0f == 0x0a0a {
		return "" // GREASE
	}
	return fmt.Sprintf("0x%04x", v)
}

// parseHello parses a TLS ClientHello (typ 1) or ServerHello (typ 2) from
// bytes that start at the handshake message (after the 5-byte record header).
func parseHello(h []byte, typ byte) (*tlsHello, bool) {
	if len(h) < 4 || h[0] != typ {
		return nil, false
	}
	r := &rd{b: h, i: 4}
	out := &tlsHello{}
	r.skip(2 + 32) // legacy version + random
	r.skip(r.u8()) // session id
	if typ == 1 {
		r.skip(r.u16()) // cipher suites
		r.skip(r.u8())  // compression
	} else {
		out.cipher = fmt.Sprintf("0x%04x", r.u16())
		r.skip(1)
	}
	extLen := r.u16()
	end := r.i + extLen
	if end > len(h) {
		end = len(h)
	}
	for !r.bad && r.i+4 <= end {
		et := r.u16()
		el := r.u16()
		ed := r.bytes(el)
		if ed == nil {
			break
		}
		x := &rd{b: ed}
		switch et {
		case 0: // server_name
			x.u16()
			if x.u8() == 0 {
				if n := x.bytes(x.u16()); n != nil {
					out.sni = string(n)
				}
			}
		case 16: // ALPN
			l := x.u16()
			stop := x.i + l
			for !x.bad && x.i < stop {
				if s := x.bytes(x.u8()); s != nil {
					out.alpn = append(out.alpn, string(s))
				}
			}
		case 43: // supported_versions
			if typ == 1 {
				l := x.u8()
				for k := 0; k < l/2; k++ {
					if v := tlsVersion(x.u16()); v != "" {
						out.versions = append(out.versions, v)
					}
				}
			} else if el == 2 {
				out.versions = []string{tlsVersion(x.u16())}
			}
		}
	}
	return out, out.sni != "" || !r.bad
}

// hexDump renders up to 256 bytes like `xxd`.
func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		j := min(i+16, len(b))
		fmt.Fprintf(&sb, "%04x  ", i)
		for k := i; k < i+16; k++ {
			if k < j {
				fmt.Fprintf(&sb, "%02x ", b[k])
			} else {
				sb.WriteString("   ")
			}
			if k == i+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" ")
		for k := i; k < j; k++ {
			c := b[k]
			if c < 32 || c > 126 {
				c = '.'
			}
			sb.WriteByte(c)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
