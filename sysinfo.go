package main

// Information about this machine: its own addresses (to tell inbound from
// outbound) and a socket→process map from lsof, used when a packet arrives
// without PKTAP process metadata.

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type procInfo struct {
	name string
	pid  int
}

type sysInfo struct {
	mu       sync.RWMutex
	local    map[string]bool
	ifaces   map[string]string // ip -> interface name
	portProc map[string]procInfo
	pidNames map[int]string // full process names from ps (kernel names are cut to 16 chars)
	pidPaths map[int]string // executable path per pid
	sigs     map[string]*exeSig
	sigQueue chan string
}

func newSysInfo() *sysInfo {
	s := &sysInfo{local: map[string]bool{}, ifaces: map[string]string{}, portProc: map[string]procInfo{}, pidNames: map[int]string{},
		pidPaths: map[int]string{}, sigs: map[string]*exeSig{}, sigQueue: make(chan string, 256)}
	go s.sigWorker()
	s.refreshPids()
	s.refreshAddrs()
	s.refreshLsof()
	go func() {
		t := time.NewTicker(3 * time.Second)
		n := 0
		for range t.C {
			n++
			s.refreshLsof()
			s.refreshPids()
			if n%5 == 0 {
				s.refreshAddrs()
			}
		}
	}()
	return s
}

func (s *sysInfo) refreshAddrs() {
	local, ifn := map[string]bool{}, map[string]string{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				local[ip.String()] = true
				ifn[ip.String()] = i.Name
			}
		}
	}
	s.mu.Lock()
	s.local, s.ifaces = local, ifn
	s.mu.Unlock()
}

func (s *sysInfo) isLocal(ip string) bool {
	if i := strings.IndexByte(ip, '%'); i >= 0 {
		ip = ip[:i]
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.local[ip]
}

func (s *sysInfo) localIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for ip := range s.local {
		out = append(out, s.ifaces[ip]+" "+ip)
	}
	return out
}

func (s *sysInfo) refreshLsof() {
	out, err := exec.Command("lsof", "+c", "0", "-nP", "-i", "-F", "pcPn").Output()
	if err != nil && len(out) == 0 {
		return
	}
	m := map[string]procInfo{}
	var cur procInfo
	var proto string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			continue
		}
		v := l[1:]
		switch l[0] {
		case 'p':
			cur.pid, _ = strconv.Atoi(v)
		case 'c':
			cur.name = strings.ReplaceAll(v, `\x20`, " ")
		case 'P':
			proto = v
		case 'n':
			local, _, _ := strings.Cut(v, "->")
			if i := strings.LastIndexByte(local, ':'); i >= 0 {
				m[proto+":"+local[i+1:]] = cur
			}
		}
	}
	s.mu.Lock()
	s.portProc = m
	s.mu.Unlock()
}

func (s *sysInfo) procFor(proto string, port int) (procInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.portProc[proto+":"+strconv.Itoa(port)]
	return p, ok
}

// refreshPids maps every running process ID to its full executable name.
func (s *sysInfo) refreshPids() {
	out, err := exec.Command("ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return
	}
	m, paths := map[int]string{}, map[int]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.TrimSpace(sc.Text())
		pidStr, path, ok := strings.Cut(f, " ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		path = strings.TrimSpace(path)
		m[pid] = baseName(path)
		paths[pid] = path
	}
	s.mu.Lock()
	for pid, n := range s.pidNames { // keep names of processes that just exited
		if _, ok := m[pid]; !ok && len(m) < 50000 {
			m[pid] = n
			if p, ok := s.pidPaths[pid]; ok {
				paths[pid] = p
			}
		}
	}
	s.pidNames, s.pidPaths = m, paths
	s.mu.Unlock()
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// fullName returns the untruncated name for pid when short is a 16-char
// kernel name; otherwise it returns short unchanged.
func (s *sysInfo) fullName(pid int, short string) string {
	if pid <= 0 || len(short) < 15 {
		return short
	}
	s.mu.RLock()
	n, ok := s.pidNames[pid]
	s.mu.RUnlock()
	if !ok { // process newer than the last refresh: ask once and remember
		out, _ := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
		full := strings.TrimSpace(string(out))
		n = baseName(full)
		s.mu.Lock()
		s.pidNames[pid] = n
		if full != "" {
			s.pidPaths[pid] = full
		}
		s.mu.Unlock()
	}
	if len(n) > len(short) && strings.HasPrefix(n, short) {
		return n
	}
	return short
}

// ---------- executable path + code signature ----------

type exeSig struct {
	Signer string // "Apple", "Google LLC", "ad-hoc", "not signed", "unknown"
	Team   string
	Apple  bool
	Known  bool // signed by Apple, App Store or an identified developer
	Done   bool
}

// exe returns the executable path for pid and its signature (Done=false
// while the check is still queued).
func (s *sysInfo) exe(pid int) (string, exeSig) {
	if pid <= 0 {
		return "", exeSig{}
	}
	s.mu.RLock()
	path := s.pidPaths[pid]
	sig := s.sigs[path]
	s.mu.RUnlock()
	if path == "" {
		return "", exeSig{}
	}
	if sig == nil {
		s.mu.Lock()
		if s.sigs[path] == nil {
			s.sigs[path] = &exeSig{}
			select {
			case s.sigQueue <- path:
			default:
				delete(s.sigs, path) // queue full; retry later
			}
		}
		s.mu.Unlock()
		return path, exeSig{}
	}
	return path, *sig
}

func (s *sysInfo) sigWorker() {
	for path := range s.sigQueue {
		sig := checkSignature(path)
		s.mu.Lock()
		s.sigs[path] = &sig
		s.mu.Unlock()
	}
}

func checkSignature(path string) exeSig {
	if !strings.HasPrefix(path, "/") {
		return exeSig{Signer: "unknown (no access)", Done: true}
	}
	out, _ := exec.Command("codesign", "-dv", "--verbose=2", path).CombinedOutput()
	text := string(out)
	sig := exeSig{Done: true}
	for _, l := range strings.Split(text, "\n") {
		if t, ok := strings.CutPrefix(l, "TeamIdentifier="); ok && t != "not set" {
			sig.Team = t
		}
	}
	switch {
	case strings.Contains(text, "not signed at all"):
		sig.Signer = "not signed"
	case strings.Contains(text, "Signature=adhoc"):
		sig.Signer = "ad-hoc (no identified developer)"
	case strings.Contains(text, "Authority=Software Signing"):
		sig.Signer, sig.Apple, sig.Known = "Apple", true, true
	case strings.Contains(text, "Authority=Apple Mac OS Application Signing"):
		sig.Signer, sig.Known = "Mac App Store", true
	default:
		for _, l := range strings.Split(text, "\n") {
			if v, ok := strings.CutPrefix(l, "Authority=Developer ID Application: "); ok {
				if i := strings.LastIndex(v, " ("); i > 0 {
					v = v[:i]
				}
				sig.Signer, sig.Known = v, true
				break
			}
			if v, ok := strings.CutPrefix(l, "Authority=Apple Development: "); ok {
				sig.Signer = "Apple Development (dev build: " + v + ")"
				break
			}
		}
		if sig.Signer == "" {
			if strings.Contains(text, "No such file") {
				sig.Signer = "unknown (file gone)"
			} else {
				sig.Signer = "unknown"
			}
		}
	}
	return sig
}
