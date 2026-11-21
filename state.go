package main

// Aggregation: turns the packet stream into connections, per-app totals,
// remote hosts, a DNS log and a traffic-over-time series.

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ringSize    = 5000
	maxConns    = 6000
	maxHosts    = 4000
	seriesLen   = 180
	activeAfter = 60.0 // seconds; a connection silent longer than this is "idle"
)

type Conn struct {
	ID        int64    `json:"id"`
	Proto     string   `json:"proto"`
	App       string   `json:"app"`
	PID       int      `json:"pid"`
	EApp      string   `json:"eapp,omitempty"`
	LIP       string   `json:"lip"`
	LPort     int      `json:"lport"`
	RIP       string   `json:"rip"`
	RPort     int      `json:"rport"`
	Service   string   `json:"service"`
	Host      string   `json:"host"`
	Owner     string   `json:"owner"`
	BytesIn   int64    `json:"bin"`
	BytesOut  int64    `json:"bout"`
	PktsIn    int64    `json:"pin"`
	PktsOut   int64    `json:"pout"`
	First     float64  `json:"first"`
	Last      float64  `json:"last"`
	State     string   `json:"state"`
	SNI       string   `json:"sni,omitempty"`
	ALPN      string   `json:"alpn,omitempty"`
	TLSVer    string   `json:"tls,omitempty"`
	Iface     string   `json:"iface"`
	Initiator string   `json:"initiator,omitempty"` // "this Mac" or "remote"
	Flags     []string `json:"flags,omitempty"`

	quic             bool
	syn, fin, rst    bool
	estab            bool
	tlsBuf           []byte
	tlsDone, srvDone bool
}

type AppStat struct {
	Name     string   `json:"name"`
	PIDs     []int    `json:"pids"`
	BytesIn  int64    `json:"bin"`
	BytesOut int64    `json:"bout"`
	PktsIn   int64    `json:"pin"`
	PktsOut  int64    `json:"pout"`
	RateIn   float64  `json:"rin"`
	RateOut  float64  `json:"rout"`
	Active   int      `json:"active"`
	Conns    int      `json:"conns"`
	Hosts    int      `json:"hosts"`
	Last     float64  `json:"last"`
	Path     string   `json:"path,omitempty"`
	Signer   string   `json:"signer,omitempty"`
	Flags    []string `json:"flags,omitempty"`

	pids  map[int]bool
	hosts map[string]bool
	hist  [][3]float64
}

type HostStat struct {
	IP       string   `json:"ip"`
	Name     string   `json:"name"`
	Owner    string   `json:"owner"`
	BytesIn  int64    `json:"bin"`
	BytesOut int64    `json:"bout"`
	Apps     []string `json:"apps"`
	Conns    int      `json:"conns"`
	Ports    []int    `json:"ports"`
	First    float64  `json:"first"`
	Last     float64  `json:"last"`

	apps  map[string]bool
	ports map[int]bool
}

type DNSEntry struct {
	T       float64 `json:"t"`
	App     string  `json:"app"`
	Kind    string  `json:"kind"`
	Proto   string  `json:"proto"`
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Answers string  `json:"answers"`
	Result  string  `json:"result"`
	Server  string  `json:"server"`
}

type Totals struct {
	BytesIn    int64 `json:"bin"`
	BytesOut   int64 `json:"bout"`
	PktsIn     int64 `json:"pin"`
	PktsOut    int64 `json:"pout"`
	PktsLocal  int64 `json:"plocal"`
	BytesLocal int64 `json:"blocal"`
}

type State struct {
	mu      sync.Mutex
	sys     *sysInfo
	ring    []*Packet
	base    int64 // ids <= base were cleared
	nextID  int64
	connSeq int64
	conns   map[string]*Conn
	apps    map[string]*AppStat
	hosts   map[string]*HostStat
	dns     []DNSEntry
	ipNames map[string]string
	totals  Totals
	series  [][3]float64 // unix sec, bytes in, bytes out
	bin     [3]float64
	started time.Time

	beacons    map[string]*beacon
	dnsServers map[string]*dnsSrv
	nxRandom   []nxName

	Status    string
	Error     string
	Capturing bool
	Pktap     bool
	Filter    string
	Source    string
	Seen      map[string]int
}

func newState(sys *sysInfo) *State {
	s := &State{sys: sys, started: time.Now()}
	s.reset()
	go func() {
		for range time.Tick(time.Second) {
			s.tick()
		}
	}()
	return s
}

func (s *State) reset() {
	s.ring = make([]*Packet, ringSize)
	s.base = s.nextID
	s.conns = map[string]*Conn{}
	s.apps = map[string]*AppStat{}
	s.hosts = map[string]*HostStat{}
	s.dns = nil
	if s.ipNames == nil {
		s.ipNames = map[string]string{}
	}
	s.totals = Totals{}
	s.beacons, s.dnsServers, s.nxRandom = nil, nil, nil
	s.series = nil
	s.bin = [3]float64{float64(time.Now().Unix()), 0, 0}
	s.started = time.Now()
}

func (s *State) Reset() {
	s.mu.Lock()
	s.reset()
	s.mu.Unlock()
}

func (s *State) setStatus(status, errMsg string) {
	s.mu.Lock()
	if status != "" {
		s.Status = status
	}
	if errMsg != "" {
		s.Error = errMsg
	}
	s.mu.Unlock()
}

// roll closes per-second bins up to now (must hold mu).
func (s *State) roll(now int64) {
	for int64(s.bin[0]) < now {
		s.series = append(s.series, s.bin)
		if len(s.series) > seriesLen {
			s.series = s.series[len(s.series)-seriesLen:]
		}
		next := s.bin[0] + 1
		if now-int64(next) > seriesLen {
			next = float64(now - seriesLen)
		}
		s.bin = [3]float64{next, 0, 0}
	}
}

func (s *State) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.roll(now.Unix())
	t := float64(now.UnixNano()) / 1e9
	for _, a := range s.apps {
		a.hist = append(a.hist, [3]float64{t, float64(a.BytesIn), float64(a.BytesOut)})
		if len(a.hist) > 6 {
			a.hist = a.hist[len(a.hist)-6:]
		}
		if n := len(a.hist); n >= 2 {
			dt := a.hist[n-1][0] - a.hist[0][0]
			if dt > 0 {
				a.RateIn = (a.hist[n-1][1] - a.hist[0][1]) / dt
				a.RateOut = (a.hist[n-1][2] - a.hist[0][2]) / dt
			}
		}
	}
}

func (s *State) ingest(p *Packet) {
	// Direction: trust PKTAP, otherwise compare against our own addresses.
	srcLocal, dstLocal := s.sys.isLocal(p.Src), s.sys.isLocal(p.Dst)
	if !p.dirKnown {
		switch {
		case srcLocal && dstLocal:
			p.Dir = "local"
		case srcLocal:
			p.Dir = "out"
		default:
			p.Dir = "in"
		}
	} else if srcLocal && dstLocal {
		p.Dir = "local"
	}
	// Local and remote ends of the conversation.
	lip, lport, rip, rport := p.Dst, p.Dport, p.Src, p.Sport
	if p.Dir == "out" || (p.Dir == "local" && p.Sport > p.Dport) {
		lip, lport, rip, rport = p.Src, p.Sport, p.Dst, p.Dport
	}
	// App fallback via lsof.
	if p.App == "" && p.l4ok && lport > 0 {
		if pi, ok := s.sys.procFor(p.Proto, lport); ok {
			p.App, p.PID = pi.name, pi.pid
			p.add("Process source", "lsof (socket table)")
		}
	} else if p.kernelMeta {
		p.App = s.sys.fullName(p.PID, p.App)
		p.add("Process source", "kernel (capture metadata)")
	}
	if p.EApp != "" {
		p.EApp = s.sys.fullName(p.ePID, p.EApp)
		if p.EApp == p.App {
			p.EApp = ""
		} else {
			p.add("On behalf of", fmt.Sprintf("%s (pid %d)", p.EApp, p.ePID))
		}
	}
	app := p.App
	if app == "" {
		app = "(unattributed)"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.roll(now.Unix())

	if p.kernelMeta {
		s.Pktap = true
	}

	switch p.Dir {
	case "in":
		s.totals.BytesIn += int64(p.Len)
		s.totals.PktsIn++
		s.bin[1] += float64(p.Len)
	case "out":
		s.totals.BytesOut += int64(p.Len)
		s.totals.PktsOut++
		s.bin[2] += float64(p.Len)
	default:
		s.totals.BytesLocal += int64(p.Len)
		s.totals.PktsLocal++
	}

	// DNS answers teach us names for IPs.
	if p.dns != nil {
		qn, qt := p.dns.qname()
		e := DNSEntry{T: p.T, App: app, Name: qn, Type: qt, Proto: p.Layers[len(p.Layers)-1]}
		if p.dns.Response {
			e.Kind, e.Answers, e.Result, e.Server = "response", p.dns.answerStr(), rcodes[p.dns.RCode], p.Src
			for _, a := range p.dns.Answers {
				if a.Type == 1 || a.Type == 28 {
					name := qn
					if name == "" || strings.HasSuffix(name, ".arpa") {
						name = a.Name
					}
					s.ipNames[a.Value] = name
				}
			}
		} else {
			e.Kind, e.Server = "query", p.Dst
		}
		s.dns = append(s.dns, e)
		if len(s.dns) > 2000 {
			s.dns = s.dns[len(s.dns)-1500:]
		}
	}

	s.track(p, app, rip)

	var c *Conn
	if p.l4ok && rip != "" {
		key := fmt.Sprintf("%s|%s|%d|%s|%d", p.Proto, lip, lport, rip, rport)
		c = s.conns[key]
		if c == nil {
			s.connSeq++
			c = &Conn{ID: s.connSeq, Proto: p.Proto, LIP: lip, LPort: lport, RIP: rip, RPort: rport,
				First: p.T, Owner: ownerOf(rip), Iface: p.Iface}
			if p.tcpFlags&synF != 0 && p.tcpFlags&ackF == 0 {
				if p.Dir == "out" {
					c.Initiator = "this Mac"
				} else {
					c.Initiator = "remote"
				}
			}
			s.conns[key] = c
			if len(s.conns) > maxConns {
				s.pruneConns()
			}
		}
		if c.App == "" || c.App == "(unattributed)" {
			c.App, c.PID = app, p.PID
		}
		if p.EApp != "" {
			c.EApp = p.EApp
		}
		c.Last = p.T
		if p.Dir == "out" {
			c.BytesOut += int64(p.Len)
			c.PktsOut++
		} else {
			c.BytesIn += int64(p.Len)
			c.PktsIn++
		}
		if p.Proto == "TCP" {
			f := p.tcpFlags
			c.syn = c.syn || f&synF != 0
			c.fin = c.fin || f&finF != 0
			c.rst = c.rst || f&rstF != 0
			c.estab = c.estab || (f&ackF != 0 && f&synF == 0)
			s.inspectTLS(c, p)
		}
		if containsLayer(p, "QUIC") {
			c.quic = true
		}
		if p.Host != "" && c.Host == "" {
			c.Host = p.Host
		}
		c.Service = serviceFor(p.Proto, lport, rport, c.quic)
	}

	// Name for display.
	if c != nil {
		if c.SNI != "" {
			p.Host = c.SNI
		} else if p.Host == "" {
			p.Host = s.ipNames[rip]
		}
	} else if p.Host == "" {
		p.Host = s.ipNames[rip]
	}
	if p.Host != "" {
		p.add("Remote host name", p.Host)
	}
	if o := ownerOf(rip); o != "" {
		p.add("Remote owner (approx.)", o)
	}

	// Apps.
	a := s.apps[app]
	if a == nil {
		a = &AppStat{Name: app, pids: map[int]bool{}, hosts: map[string]bool{}}
		s.apps[app] = a
	}
	if p.PID > 0 {
		a.pids[p.PID] = true
	}
	if rip != "" && !isLocalScope(rip) {
		a.hosts[rip] = true
	}
	a.Last = p.T
	if p.Dir == "out" {
		a.BytesOut += int64(p.Len)
		a.PktsOut++
	} else {
		a.BytesIn += int64(p.Len)
		a.PktsIn++
	}

	// Hosts.
	if rip != "" {
		h := s.hosts[rip]
		if h == nil {
			h = &HostStat{IP: rip, Owner: ownerOf(rip), First: p.T, apps: map[string]bool{}, ports: map[int]bool{}}
			s.hosts[rip] = h
			if len(s.hosts) > maxHosts {
				s.pruneHosts()
			}
		}
		h.Last = p.T
		h.apps[app] = true
		if rport > 0 && len(h.ports) < 20 {
			h.ports[rport] = true
		}
		if p.Dir == "out" {
			h.BytesOut += int64(p.Len)
		} else {
			h.BytesIn += int64(p.Len)
		}
		if c != nil && c.SNI != "" {
			h.Name = c.SNI
		}
	}

	s.nextID++
	p.ID = s.nextID
	s.ring[int((p.ID-1)%ringSize)] = p
}

func containsLayer(p *Packet, l string) bool {
	for _, x := range p.Layers {
		if x == l {
			return true
		}
	}
	return false
}

// inspectTLS reassembles the first TLS handshake message in each direction
// (ClientHello can span several TCP segments) and extracts the server name.
func (s *State) inspectTLS(c *Conn, p *Packet) {
	b := p.payload
	if len(b) == 0 {
		return
	}
	isRecord := len(b) >= 5 && b[0] >= 20 && b[0] <= 23 && b[1] == 3
	if isRecord {
		names := map[byte]string{20: "TLS ChangeCipherSpec", 21: "TLS alert", 22: "TLS handshake", 23: "TLS encrypted data"}
		p.Layers = append(p.Layers, "TLS")
		p.Info = fmt.Sprintf("%s · %d bytes", names[b[0]], p.payLen)
	}
	clientSide := p.Dir == "out"
	if c.Initiator == "remote" {
		clientSide = !clientSide
	}
	if clientSide && !c.tlsDone {
		if c.tlsBuf == nil && isRecord && b[0] == 22 && len(b) > 5 && b[5] == 1 {
			c.tlsBuf = append([]byte(nil), b...)
		} else if c.tlsBuf != nil {
			c.tlsBuf = append(c.tlsBuf, b...)
		}
		if c.tlsBuf != nil {
			buf := c.tlsBuf
			need := 5 + int(buf[3])<<8 | int(buf[4])
			complete := len(buf) >= need || len(buf) > 16384
			if h, _ := parseHello(buf[5:min(len(buf), need)], 1); h != nil && (h.sni != "" || complete) {
				c.SNI = h.sni
				c.ALPN = strings.Join(h.alpn, ", ")
				c.tlsDone, c.tlsBuf = true, nil
				p.Info = "TLS ClientHello → " + orDash(h.sni)
				if !containsLayer(p, "TLS") {
					p.Layers = append(p.Layers, "TLS")
				}
				p.add("TLS server name (SNI)", h.sni)
				p.add("TLS ALPN", c.ALPN)
				p.add("TLS versions offered", strings.Join(h.versions, ", "))
				if h.sni != "" {
					s.ipNames[c.RIP] = h.sni
				}
			} else if complete {
				c.tlsDone, c.tlsBuf = true, nil
			}
		}
	}
	if !clientSide && !c.srvDone && isRecord && b[0] == 22 && len(b) > 5 && b[5] == 2 {
		c.srvDone = true
		end := min(len(b), 5+(int(b[3])<<8|int(b[4])))
		if h, _ := parseHello(b[5:end], 2); h != nil {
			ver := "TLS 1.2 or older"
			if len(h.versions) > 0 {
				ver = h.versions[0]
			}
			c.TLSVer = ver
			p.Info = "TLS ServerHello (" + ver + ")"
			p.add("TLS version chosen", ver)
			p.add("TLS cipher suite", h.cipher)
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (s *State) pruneConns() {
	type kv struct {
		k string
		t float64
	}
	var l []kv
	for k, c := range s.conns {
		l = append(l, kv{k, c.Last})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].t < l[j].t })
	for _, x := range l[:len(l)/5] {
		delete(s.conns, x.k)
	}
}

func (s *State) pruneHosts() {
	type kv struct {
		k string
		t float64
	}
	var l []kv
	for k, h := range s.hosts {
		l = append(l, kv{k, h.Last})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].t < l[j].t })
	for _, x := range l[:len(l)/5] {
		delete(s.hosts, x.k)
	}
}

func connState(c *Conn, now float64) string {
	idle := now-c.Last > activeAfter
	if c.Proto != "TCP" {
		if idle {
			return "idle"
		}
		return "active"
	}
	switch {
	case c.rst:
		return "reset"
	case c.fin:
		return "closed"
	case idle:
		return "idle"
	case c.syn && !c.estab:
		return "connecting"
	}
	return "open"
}

type Snapshot struct {
	Status    string         `json:"status"`
	Error     string         `json:"error"`
	Capturing bool           `json:"capturing"`
	Pktap     bool           `json:"pktap"`
	Filter    string         `json:"filter"`
	Source    string         `json:"source"`
	Started   float64        `json:"started"`
	Now       float64        `json:"now"`
	Totals    Totals         `json:"totals"`
	Series    [][3]float64   `json:"series"`
	Packets   []Packet       `json:"packets"`
	LastID    int64          `json:"last_id"`
	Apps      []AppStat      `json:"apps"`
	Conns     []Conn         `json:"conns"`
	Hosts     []HostStat     `json:"hosts"`
	DNS       []DNSEntry     `json:"dns"`
	LocalIPs  []string       `json:"local_ips"`
	Counts    map[string]int `json:"counts"`
	Formats   map[string]int `json:"formats,omitempty"`
	Findings  []Finding      `json:"findings"`
}

func (s *State) snapshot(since int64) Snapshot {
	local := s.sys.localIPs()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := float64(time.Now().UnixNano()) / 1e9
	snap := Snapshot{Status: s.Status, Error: s.Error, Capturing: s.Capturing, Pktap: s.Pktap,
		Filter: s.Filter, Source: s.Source, Started: float64(s.started.Unix()), Now: now,
		Totals: s.totals, LastID: s.nextID, LocalIPs: local}
	snap.Series = append(snap.Series, s.series...)

	// New packets (newest 600 at most), summary only.
	from := since + 1
	if s.nextID-from >= 600 {
		from = s.nextID - 599
	}
	if lo := s.oldestID(); from < lo {
		from = lo
	}
	for id := from; id <= s.nextID; id++ {
		p := *s.ring[int((id-1)%ringSize)]
		p.Fields, p.Hex = nil, ""
		snap.Packets = append(snap.Packets, p)
	}

	findings, connFlags, appFlags := s.findings(now)
	snap.Findings = findings

	active := map[string]int{}
	total := map[string]int{}
	for _, c := range s.conns {
		total[c.App]++
		if now-c.Last <= activeAfter {
			active[c.App]++
		}
	}
	for _, a := range s.apps {
		x := *a
		x.PIDs = nil
		for pid := range a.pids {
			x.PIDs = append(x.PIDs, pid)
		}
		sort.Ints(x.PIDs)
		x.Active, x.Conns, x.Hosts = active[a.Name], total[a.Name], len(a.hosts)
		x.Flags = appFlags[a.Name]
		x.hist = nil
		snap.Apps = append(snap.Apps, x)
	}
	sort.Slice(snap.Apps, func(i, j int) bool {
		ri, rj := snap.Apps[i].RateIn+snap.Apps[i].RateOut, snap.Apps[j].RateIn+snap.Apps[j].RateOut
		if ri != rj {
			return ri > rj
		}
		return snap.Apps[i].BytesIn+snap.Apps[i].BytesOut > snap.Apps[j].BytesIn+snap.Apps[j].BytesOut
	})

	for _, c := range s.conns {
		x := *c
		x.State = connState(c, now)
		x.Flags = connFlags[c.ID]
		if x.Host == "" {
			if x.SNI != "" {
				x.Host = x.SNI
			} else {
				x.Host = s.ipNames[c.RIP]
			}
		}
		x.tlsBuf = nil
		snap.Conns = append(snap.Conns, x)
	}
	sort.Slice(snap.Conns, func(i, j int) bool { return snap.Conns[i].Last > snap.Conns[j].Last })
	if len(snap.Conns) > 1000 {
		snap.Conns = snap.Conns[:1000]
	}

	connsPerHost := map[string]int{}
	for _, c := range s.conns {
		connsPerHost[c.RIP]++
	}
	for _, h := range s.hosts {
		x := *h
		if x.Name == "" {
			x.Name = s.ipNames[h.IP]
		}
		for a := range h.apps {
			x.Apps = append(x.Apps, a)
		}
		sort.Strings(x.Apps)
		for pt := range h.ports {
			x.Ports = append(x.Ports, pt)
		}
		sort.Ints(x.Ports)
		x.Conns = connsPerHost[h.IP]
		snap.Hosts = append(snap.Hosts, x)
	}
	sort.Slice(snap.Hosts, func(i, j int) bool {
		return snap.Hosts[i].BytesIn+snap.Hosts[i].BytesOut > snap.Hosts[j].BytesIn+snap.Hosts[j].BytesOut
	})
	if len(snap.Hosts) > 600 {
		snap.Hosts = snap.Hosts[:600]
	}

	n := len(s.dns)
	for i := n - 1; i >= 0 && i >= n-500; i-- {
		snap.DNS = append(snap.DNS, s.dns[i])
	}
	snap.Formats = s.Seen
	snap.Counts = map[string]int{"apps": len(s.apps), "conns": len(s.conns), "hosts": len(s.hosts), "dns": len(s.dns)}
	return snap
}

func (s *State) packet(id int64) (Packet, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id < s.oldestID() || id > s.nextID {
		return Packet{}, false
	}
	p := *s.ring[int((id-1)%ringSize)]
	p.Fields = append([][2]string(nil), p.Fields...)
	p.Hex = hexDump(p.head)
	return p, true
}

func (s *State) oldestID() int64 {
	lo := s.nextID - ringSize + 1
	if lo <= s.base {
		lo = s.base + 1
	}
	return lo
}
