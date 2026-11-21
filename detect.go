package main

// "Worth a look": simple, explainable rules that point at traffic worth a
// second glance. None of them proves anything is malicious — each finding
// says why it was flagged and why it might be perfectly fine.

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
)

type Finding struct {
	Key    string  `json:"key"`
	Sev    string  `json:"sev"` // high | medium | low
	Rule   string  `json:"rule"`
	Title  string  `json:"title"`
	Detail string  `json:"detail"`
	Benign string  `json:"benign"`
	Check  string  `json:"check"`
	App    string  `json:"app"`
	Target string  `json:"target"`
	IP     string  `json:"ip,omitempty"`
	First  float64 `json:"first"`
	Last   float64 `json:"last"`
	Count  int     `json:"count"`
}

var sevRank = map[string]int{"high": 3, "medium": 2, "low": 1}

// Ports that are commonly abused by remote-access tools, proxies, miners, etc.
var riskyPorts = map[int]string{
	23: "Telnet (unencrypted remote login)", 1080: "SOCKS proxy", 1337: "often used by hacking tools",
	3389: "Windows Remote Desktop", 4444: "default port of Metasploit / remote-access tools",
	5555: "Android debug / remote-access tools", 5900: "VNC screen sharing", 6666: "IRC (old botnet control)",
	6667: "IRC (old botnet control)", 6697: "IRC over TLS", 8333: "Bitcoin node", 9001: "Tor relay",
	9030: "Tor directory", 9050: "Tor SOCKS proxy", 9150: "Tor Browser proxy", 12345: "often used by backdoors",
	31337: "classic backdoor port", 3333: "crypto-mining pool", 14444: "crypto-mining pool",
	45700: "crypto-mining pool",
}

// Ports normal desktop software uses; anything else on a public address is "unusual".
var commonPorts = map[int]bool{
	22: true, 53: true, 80: true, 123: true, 443: true, 465: true, 587: true, 853: true, 993: true, 995: true,
	143: true, 110: true, 25: true, 3478: true, 5223: true, 5228: true, 8080: true, 8443: true, 19302: true,
	4070: true, 9418: true, 2195: true, 2197: true, 5222: true, 1194: true, 500: true, 4500: true, 51820: true,
	3479: true, 3480: true, 3481: true, 19305: true, 19306: true, 19307: true, 19308: true, 19309: true,
}

var publicResolvers = map[string]string{
	"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
	"9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
	"94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
	"2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
	"2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google", "2620:fe::fe": "Quad9",
}

// Names of macOS system processes; one of these not signed by Apple is a red flag.
var systemNames = map[string]bool{
	"launchd": true, "kernel_task": true, "mDNSResponder": true, "nsurlsessiond": true, "apsd": true,
	"cloudd": true, "rapportd": true, "sharingd": true, "trustd": true, "Finder": true, "Dock": true,
	"WindowServer": true, "softwareupdated": true, "syspolicyd": true, "configd": true,
	"identityservicesd": true, "sshd": true, "loginwindow": true, "SystemUIServer": true, "coreaudiod": true,
	"bluetoothd": true, "airportd": true, "netbiosd": true, "symptomsd": true, "locationd": true,
}

// ---------- trackers fed from ingest (caller holds s.mu) ----------

type beacon struct {
	last   float64
	bursts []float64
	app    string
	ip     string
}

type dnsSrv struct {
	apps        map[string]bool
	n           int
	first, last float64
}

type nxName struct {
	name string
	t    float64
}

func (s *State) track(p *Packet, app, rip string) {
	if s.beacons == nil {
		s.beacons, s.dnsServers = map[string]*beacon{}, map[string]*dnsSrv{}
	}
	if rip != "" && !isLocalScope(rip) && app != "(unattributed)" {
		k := app + "|" + rip
		b := s.beacons[k]
		if b == nil {
			if len(s.beacons) > 8000 {
				s.beacons = map[string]*beacon{}
			}
			b = &beacon{app: app, ip: rip}
			s.beacons[k] = b
		}
		if p.T-b.last > 4 { // a new burst of activity after >4s of silence
			b.bursts = append(b.bursts, p.T)
			if len(b.bursts) > 16 {
				b.bursts = b.bursts[len(b.bursts)-16:]
			}
		}
		b.last = p.T
	}
	if p.dns != nil && (p.Sport == 53 || p.Dport == 53) {
		if !p.dns.Response && !isLocalScope(p.Dst) {
			d := s.dnsServers[p.Dst]
			if d == nil {
				d = &dnsSrv{apps: map[string]bool{}, first: p.T}
				s.dnsServers[p.Dst] = d
			}
			d.apps[app] = true
			d.n++
			d.last = p.T
		}
		if p.dns.Response && p.dns.RCode == 3 {
			if n, _ := p.dns.qname(); looksRandom(n) {
				s.nxRandom = append(s.nxRandom, nxName{n, p.T})
				if len(s.nxRandom) > 200 {
					s.nxRandom = s.nxRandom[len(s.nxRandom)-200:]
				}
			}
		}
	}
}

// looksRandom flags machine-generated labels such as "xk3j9q2vbn7w.top".
func looksRandom(name string) bool {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 2 {
		return false
	}
	l := labels[len(labels)-2] // registrable part, e.g. "xk3j9q2vbn7w"
	if len(l) < 10 {
		return false
	}
	return entropy(l) > 3.2 && vowelRatio(l) < 0.25
}

func entropy(s string) float64 {
	c := map[rune]float64{}
	for _, r := range s {
		c[r]++
	}
	h := 0.0
	for _, n := range c {
		p := n / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}

func vowelRatio(s string) float64 {
	v := 0
	for _, r := range strings.ToLower(s) {
		if strings.ContainsRune("aeiou", r) {
			v++
		}
	}
	return float64(v) / float64(len(s))
}

func isPublic(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && !isLocalScope(ip) && !a.IsUnspecified()
}

// ---------- rule evaluation (caller holds s.mu) ----------

type findingSet struct {
	m        map[string]*Finding
	connFlag map[int64][]string
	appFlag  map[string][]string
}

func (fs *findingSet) add(f Finding, first, last float64) {
	if x := fs.m[f.Key]; x != nil {
		x.Count++
		x.First = math.Min(x.First, first)
		x.Last = math.Max(x.Last, last)
		return
	}
	f.First, f.Last, f.Count = first, last, 1
	fs.m[f.Key] = &f
}

func (s *State) findings(now float64) ([]Finding, map[int64][]string, map[string][]string) {
	fs := &findingSet{m: map[string]*Finding{}, connFlag: map[int64][]string{}, appFlag: map[string][]string{}}

	// --- per app: where it runs from and who signed it ---
	for _, a := range s.apps {
		if a.Name == "(unattributed)" {
			continue
		}
		checked := 0
		for pid := range a.pids {
			if checked++; checked > 32 {
				break
			}
			path, sig := s.sys.exe(pid)
			if path == "" {
				continue
			}
			if a.Path == "" || (sig.Done && !sig.Known) {
				a.Path = path // show the most interesting copy
				if sig.Done {
					a.Signer = sig.Signer
				}
			}
			loc := oddLocation(path)
			unsigned := sig.Done && !sig.Known && !strings.HasPrefix(sig.Signer, "unknown")
			switch {
			case sig.Done && systemNames[baseName(path)] && !sig.Apple:
				fs.add(Finding{Key: "impostor|" + a.Name + "|" + path, Sev: "high", Rule: "Pretends to be a system process",
					Title:  a.Name + " has a macOS system name but isn't signed by Apple",
					Detail: "Runs from " + path + "; signed by: " + sig.Signer + ".",
					Benign: "Very unlikely to be fine. Real macOS components are always signed by Apple.",
					Check:  "Find the file in Finder and look at where it came from; consider a malware scan.",
					App:    a.Name, Target: path}, a.Last, a.Last)
			case loc != "" && unsigned:
				fs.add(Finding{Key: "loc|" + a.Name + "|" + path, Sev: "high", Rule: "Unsigned app in an odd location",
					Title:  a.Name + " runs from " + loc + " and isn't signed by an identified developer",
					Detail: "Path: " + path + ". Signature: " + sig.Signer + ".",
					Benign: "Could be something you just downloaded or built yourself.",
					Check:  "If you don't recognise it, quit it and check where the file came from.",
					App:    a.Name, Target: path}, a.Last, a.Last)
			case loc != "":
				fs.add(Finding{Key: "loc|" + a.Name + "|" + path, Sev: "medium", Rule: "App runs from an odd location",
					Title:  a.Name + " runs from " + loc,
					Detail: "Path: " + path + ". Installed apps normally live in /Applications or system folders.",
					Benign: "Installers and apps opened straight from Downloads or a disk image do this.",
					Check:  "Confirm you started it on purpose.",
					App:    a.Name, Target: path}, a.Last, a.Last)
			case unsigned:
				fs.add(Finding{Key: "unsigned|" + a.Name + "|" + path, Sev: "low", Rule: "Not signed by an identified developer",
					Title:  a.Name + " is " + sig.Signer,
					Detail: "Path: " + path + ". macOS can't tell who made it.",
					Benign: "Normal for Homebrew packages, developer tools and things you compiled yourself.",
					Check:  "Fine if you installed it; otherwise find out what it is.",
					App:    a.Name, Target: path}, a.Last, a.Last)
			}
		}
	}

	// --- per connection ---
	for _, c := range s.conns {
		if !isPublic(c.RIP) {
			continue
		}
		target := ep(c.RIP, c.RPort)
		name := c.Host
		if name == "" {
			name = s.ipNames[c.RIP]
		}
		if c.SNI != "" {
			name = c.SNI
		}
		label := target
		if name != "" {
			label = name + " (" + target + ")"
		}
		if c.Initiator == "remote" {
			k := "inbound|" + c.App + "|" + c.RIP + "|" + fmt.Sprint(c.LPort)
			fs.add(Finding{Key: k, Sev: "medium", Rule: "Incoming connection from the internet",
				Title:  fmt.Sprintf("%s opened a connection to %s on this Mac (port %d)", c.RIP, c.App, c.LPort),
				Detail: fmt.Sprintf("Owner: %s. Bytes in/out: %s / %s.", orUnknown(c.Owner), human(c.BytesIn), human(c.BytesOut)),
				Benign: "Expected if you run a server, a game, BitTorrent or another peer-to-peer app.",
				Check:  "Check System Settings → Network → Firewall, and whether that app should accept connections.",
				App:    c.App, Target: label, IP: c.RIP}, c.First, c.Last)
			fs.connFlag[c.ID] = append(fs.connFlag[c.ID], "medium:Incoming from internet")
		}
		port := c.RPort
		if c.Initiator == "remote" {
			port = c.LPort
		}
		if why, bad := riskyPorts[port]; bad {
			fs.add(Finding{Key: "risky|" + c.App + "|" + c.RIP + "|" + fmt.Sprint(port), Sev: "medium", Rule: "Port often used by remote-access or proxy tools",
				Title:  fmt.Sprintf("%s ⇄ %s on port %d", c.App, label, port),
				Detail: fmt.Sprintf("Port %d: %s.", port, why),
				Benign: "Fine if you use that kind of software on purpose (VNC, Tor, crypto node, etc.).",
				Check:  "Make sure " + c.App + " is something you expect to do this.",
				App:    c.App, Target: label, IP: c.RIP}, c.First, c.Last)
			fs.connFlag[c.ID] = append(fs.connFlag[c.ID], fmt.Sprintf("medium:Port %d (%s)", port, why))
		} else if !commonPorts[port] && port > 0 && port < 49152 && c.Proto == "TCP" && c.BytesIn+c.BytesOut > 2048 {
			fs.add(Finding{Key: "port|" + c.App + "|" + fmt.Sprint(port), Sev: "low", Rule: "Unusual port",
				Title:  fmt.Sprintf("%s uses port %d to reach %s", c.App, port, label),
				Detail: "Most internet traffic uses 443 (HTTPS). " + orElse(c.Service, "This port has no common meaning."),
				Benign: "Many apps use their own ports — dev tools, games, chat, VPNs.",
				Check:  "Look up the port + app name if you're unsure.",
				App:    c.App, Target: label, IP: c.RIP}, c.First, c.Last)
			fs.connFlag[c.ID] = append(fs.connFlag[c.ID], fmt.Sprintf("low:Unusual port %d", port))
		}
		if name == "" && c.Owner == "" && c.Initiator == "this Mac" && c.App != "(unattributed)" {
			fs.add(Finding{Key: "noname|" + c.App + "|" + c.RIP, Sev: "low", Rule: "Connection to an IP with no name",
				Title:  fmt.Sprintf("%s connected to %s without looking up a name", c.App, target),
				Detail: "No DNS answer or TLS server name was seen for this address, and it isn't in a known provider range.",
				Benign: "The name may have been cached before capture started, or looked up over encrypted DNS.",
				Check:  "Look the IP up on a WHOIS site to see who owns it.",
				App:    c.App, Target: target, IP: c.RIP}, c.First, c.Last)
			fs.connFlag[c.ID] = append(fs.connFlag[c.ID], "low:No hostname")
		}
	}

	// --- per app: upload-heavy ---
	for _, a := range s.apps {
		if a.BytesOut > 20<<20 && a.BytesOut > 2*a.BytesIn {
			top, topOut := "", int64(0)
			for _, h := range s.hosts {
				if h.apps[a.Name] && h.BytesOut > topOut {
					top, topOut = h.IP, h.BytesOut
				}
			}
			tl := top
			if n := s.ipNames[top]; n != "" {
				tl = n + " (" + top + ")"
			}
			fs.add(Finding{Key: "upload|" + a.Name, Sev: "medium", Rule: "Uploading much more than downloading",
				Title:  fmt.Sprintf("%s sent %s but received only %s", a.Name, human(a.BytesOut), human(a.BytesIn)),
				Detail: "Most data went to " + orUnknown(tl) + ".",
				Benign: "Backups, cloud sync (iCloud, Dropbox), video calls and file uploads look like this.",
				Check:  "Confirm " + a.Name + " is supposed to be sending files right now.",
				App:    a.Name, Target: tl, IP: top}, a.Last, a.Last)
		}
	}

	// --- regular check-ins ---
	for _, b := range s.beacons {
		n := len(b.bursts)
		if n < 6 || now-b.last > 600 {
			continue
		}
		iv := make([]float64, 0, n-1)
		for i := 1; i < n; i++ {
			iv = append(iv, b.bursts[i]-b.bursts[i-1])
		}
		mean, sd := meanSD(iv)
		if mean < 8 || sd/mean > 0.12 {
			continue
		}
		name := s.ipNames[b.ip]
		tl := b.ip
		if name != "" {
			tl = name + " (" + b.ip + ")"
		}
		fs.add(Finding{Key: "beacon|" + b.app + "|" + b.ip, Sev: "low", Rule: "Regular check-ins",
			Title:  fmt.Sprintf("%s contacts %s every ~%s like clockwork", b.app, tl, secs(mean)),
			Detail: fmt.Sprintf("%d bursts seen, spaced %s ± %s apart.", n, secs(mean), secs(sd)),
			Benign: "Push notifications, sync, keep-alives and update checks do exactly this.",
			Check:  "Only worth worrying about if the app or the destination is also unfamiliar.",
			App:    b.app, Target: tl, IP: b.ip}, b.bursts[0], b.last)
	}

	// --- DNS ---
	for ip, d := range s.dnsServers {
		if _, ok := publicResolvers[ip]; ok {
			continue
		}
		var apps []string
		for a := range d.apps {
			apps = append(apps, a)
		}
		sort.Strings(apps)
		fs.add(Finding{Key: "dnssrv|" + ip, Sev: "low", Rule: "DNS sent to an unusual server",
			Title:  fmt.Sprintf("%s sent DNS lookups to %s", strings.Join(apps, ", "), ip),
			Detail: fmt.Sprintf("%d plain-DNS queries to %s (owner: %s), not to your router or a well-known resolver.", d.n, ip, orUnknown(ownerOf(ip))),
			Benign: "VPNs, corporate networks and privacy tools often use their own DNS servers.",
			Check:  "Check System Settings → Network → DNS, and any VPN you run.",
			App:    strings.Join(apps, ", "), Target: ip, IP: ip}, d.first, d.last)
	}
	for _, e := range s.dns {
		if e.Kind != "query" {
			continue
		}
		long := len(e.Name) > 120
		for _, l := range strings.Split(e.Name, ".") {
			if len(l) > 50 {
				long = true
			}
		}
		if long {
			fs.add(Finding{Key: "longdns|" + e.App + "|" + e.Name, Sev: "medium", Rule: "Very long DNS name",
				Title:  e.App + " looked up an unusually long name",
				Detail: e.Name,
				Benign: "Some anti-spam, CDN and telemetry services encode data in names.",
				Check:  "Data can be smuggled out inside DNS names; check which app keeps doing this.",
				App:    e.App, Target: e.Name}, e.T, e.T)
		}
	}
	if len(s.nxRandom) >= 5 {
		var names []string
		first, last := s.nxRandom[0].t, s.nxRandom[len(s.nxRandom)-1].t
		for _, x := range s.nxRandom[max(0, len(s.nxRandom)-5):] {
			names = append(names, x.name)
		}
		fs.add(Finding{Key: "dga", Sev: "medium", Rule: "Failed lookups for random-looking names",
			Title:  fmt.Sprintf("%d lookups for random-looking names that don't exist", len(s.nxRandom)),
			Detail: "Recent: " + strings.Join(names, ", "),
			Benign: "Chrome checks for DNS hijacking with random names at startup; a few of those are normal.",
			Check:  "Many of these, repeatedly, is a classic sign of malware searching for its control server.",
			Target: "DNS"}, first, last)
	}

	// Flag apps that have any finding.
	out := make([]Finding, 0, len(fs.m))
	for _, f := range fs.m {
		out = append(out, *f)
		for _, a := range strings.Split(f.App, ", ") {
			if a != "" {
				fs.appFlag[a] = append(fs.appFlag[a], f.Sev+":"+f.Rule)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if sevRank[out[i].Sev] != sevRank[out[j].Sev] {
			return sevRank[out[i].Sev] > sevRank[out[j].Sev]
		}
		return out[i].Last > out[j].Last
	})
	return out, fs.connFlag, fs.appFlag
}

func oddLocation(path string) string {
	switch {
	case strings.HasPrefix(path, "/tmp/"), strings.HasPrefix(path, "/private/tmp/"), strings.HasPrefix(path, "/var/tmp/"), strings.HasPrefix(path, "/private/var/tmp/"):
		return "a temporary folder"
	case strings.HasPrefix(path, "/private/var/folders/"), strings.HasPrefix(path, "/var/folders/"):
		return "a hidden system temp folder"
	case strings.Contains(path, "/Downloads/"):
		return "Downloads"
	case strings.HasPrefix(path, "/Users/Shared/"):
		return "/Users/Shared"
	case strings.HasPrefix(path, "/Volumes/"):
		return "a mounted disk image or drive"
	case strings.Contains(path, "/.Trash/"):
		return "the Trash"
	}
	return ""
}

func meanSD(x []float64) (float64, float64) {
	if len(x) == 0 {
		return 0, 0
	}
	m := 0.0
	for _, v := range x {
		m += v
	}
	m /= float64(len(x))
	v := 0.0
	for _, y := range x {
		v += (y - m) * (y - m)
	}
	return m, math.Sqrt(v / float64(len(x)))
}

func secs(s float64) string {
	if s >= 90 {
		return fmt.Sprintf("%.1f min", s/60)
	}
	return fmt.Sprintf("%.0fs", s)
}

func human(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if f < 1024 || u == "GB" {
			if u == "B" {
				return fmt.Sprintf("%d B", n)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

func ep(ip string, port int) string {
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	if port > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return ip
}

func orUnknown(s string) string { return orElse(s, "unknown") }
func orElse(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
