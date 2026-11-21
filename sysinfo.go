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
}

func newSysInfo() *sysInfo {
	s := &sysInfo{local: map[string]bool{}, ifaces: map[string]string{}, portProc: map[string]procInfo{}, pidNames: map[int]string{}}
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
	m := map[int]string{}
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
		m[pid] = baseName(strings.TrimSpace(path))
	}
	s.mu.Lock()
	for pid, n := range s.pidNames { // keep names of processes that just exited
		if _, ok := m[pid]; !ok && len(m) < 50000 {
			m[pid] = n
		}
	}
	s.pidNames = m
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
		n = baseName(strings.TrimSpace(string(out)))
		s.mu.Lock()
		s.pidNames[pid] = n
		s.mu.Unlock()
	}
	if len(n) > len(short) && strings.HasPrefix(n, short) {
		return n
	}
	return short
}
