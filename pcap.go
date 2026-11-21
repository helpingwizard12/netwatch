package main

// Minimal readers for the two capture formats tcpdump can emit on stdout:
// classic pcap and pcapng. No cgo / libpcap needed.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

type rawFrame struct {
	ts      time.Time
	link    uint32 // link-layer type (DLT) of data
	data    []byte
	origLen int
	order   binary.ByteOrder // byte order of the writer (PKTAP headers use it)
	iface   string

	// Apple pcapng per-packet metadata (when present)
	meta  bool
	pid   int
	comm  string
	epid  int
	ecomm string
	dir   string // in | out | ""
	svc   uint32
}

type pibEntry struct {
	pid  int
	name string
}

type ngIface struct {
	link    uint32
	tsUnits float64 // ticks per second
	name    string
}

type frameReader struct {
	r      *bufio.Reader
	ng     bool
	bo     binary.ByteOrder
	link   uint32
	nano   bool
	ifaces []ngIface
	pibs   []pibEntry
	// block/option codes seen, for diagnostics
	Seen map[string]int
}

const maxFrame = 1 << 20

func newFrameReader(src io.Reader) (*frameReader, error) {
	fr := &frameReader{r: bufio.NewReaderSize(src, 1<<16), Seen: map[string]int{}}
	magic, err := fr.r.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("no capture data: %w", err)
	}
	le := binary.LittleEndian.Uint32(magic)
	switch le {
	case 0xa1b2c3d4, 0xa1b23c4d:
		fr.bo = binary.LittleEndian
		fr.nano = le == 0xa1b23c4d
	case 0xd4c3b2a1, 0x4d3cb2a1:
		fr.bo = binary.BigEndian
		fr.nano = le == 0x4d3cb2a1
	case 0x0a0d0d0a:
		fr.ng = true
		return fr, nil
	default:
		return nil, fmt.Errorf("unrecognised capture format (magic %08x)", le)
	}
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(fr.r, hdr); err != nil {
		return nil, err
	}
	fr.link = fr.bo.Uint32(hdr[20:]) & 0x0fffffff
	return fr, nil
}

func (fr *frameReader) Next() (rawFrame, error) {
	if fr.ng {
		return fr.nextNG()
	}
	h := make([]byte, 16)
	if _, err := io.ReadFull(fr.r, h); err != nil {
		return rawFrame{}, err
	}
	sec := fr.bo.Uint32(h[0:])
	frac := fr.bo.Uint32(h[4:])
	incl := fr.bo.Uint32(h[8:])
	orig := fr.bo.Uint32(h[12:])
	if incl > maxFrame {
		return rawFrame{}, errors.New("corrupt pcap record")
	}
	data := make([]byte, incl)
	if _, err := io.ReadFull(fr.r, data); err != nil {
		return rawFrame{}, err
	}
	ns := int64(frac) * 1000
	if fr.nano {
		ns = int64(frac)
	}
	return rawFrame{ts: time.Unix(int64(sec), ns), link: fr.link, data: data, origLen: int(orig), order: fr.bo}, nil
}

func (fr *frameReader) nextNG() (rawFrame, error) {
	for {
		h := make([]byte, 8)
		if _, err := io.ReadFull(fr.r, h); err != nil {
			return rawFrame{}, err
		}
		btype := binary.LittleEndian.Uint32(h[0:])
		if btype == 0x0a0d0d0a { // section header: learn byte order
			bom := make([]byte, 4)
			if _, err := io.ReadFull(fr.r, bom); err != nil {
				return rawFrame{}, err
			}
			if binary.LittleEndian.Uint32(bom) == 0x1a2b3c4d {
				fr.bo = binary.LittleEndian
			} else {
				fr.bo = binary.BigEndian
			}
			total := fr.bo.Uint32(h[4:])
			if total < 12 || total > maxFrame {
				return rawFrame{}, errors.New("corrupt pcapng section")
			}
			if _, err := fr.r.Discard(int(total) - 12); err != nil {
				return rawFrame{}, err
			}
			fr.ifaces = nil
			fr.pibs = nil
			fr.Seen["section"]++
			continue
		}
		if fr.bo == nil {
			return rawFrame{}, errors.New("pcapng block before section header")
		}
		btype = fr.bo.Uint32(h[0:])
		total := fr.bo.Uint32(h[4:])
		if total < 12 || total > maxFrame {
			return rawFrame{}, errors.New("corrupt pcapng block")
		}
		body := make([]byte, total-8)
		if _, err := io.ReadFull(fr.r, body); err != nil {
			return rawFrame{}, err
		}
		body = body[:len(body)-4] // trailing length
		if len(fr.Seen) < 64 {
			fr.Seen[fmt.Sprintf("block 0x%x", btype)]++
		}
		switch btype {
		case 0x80000001: // Apple process information block
			if len(body) < 4 {
				continue
			}
			pe := pibEntry{pid: int(int32(fr.bo.Uint32(body[0:])))}
			fr.walkOpts(body[4:], func(code uint16, v []byte) {
				if code == 2 {
					pe.name = cstr(v)
				}
			})
			fr.pibs = append(fr.pibs, pe)
		case 1: // interface description
			if len(body) < 8 {
				continue
			}
			ifc := ngIface{link: uint32(fr.bo.Uint16(body[0:])), tsUnits: 1e6}
			fr.parseIfaceOpts(&ifc, body[8:])
			fr.ifaces = append(fr.ifaces, ifc)
		case 6: // enhanced packet
			if len(body) < 20 {
				continue
			}
			id := fr.bo.Uint32(body[0:])
			ticks := uint64(fr.bo.Uint32(body[4:]))<<32 | uint64(fr.bo.Uint32(body[8:]))
			capl := fr.bo.Uint32(body[12:])
			orig := fr.bo.Uint32(body[16:])
			if int(capl) > len(body)-20 {
				capl = uint32(len(body) - 20)
			}
			ifc := ngIface{link: 1, tsUnits: 1e6}
			if int(id) < len(fr.ifaces) {
				ifc = fr.ifaces[id]
			}
			secs := float64(ticks) / ifc.tsUnits
			data := append([]byte(nil), body[20:20+capl]...)
			f := rawFrame{ts: time.Unix(0, int64(secs*1e9)), link: ifc.link, data: data, origLen: int(orig), order: fr.bo, iface: ifc.name}
			if optStart := 20 + (int(capl)+3)/4*4; optStart < len(body) {
				fr.epbOpts(&f, body[optStart:])
			}
			return f, nil
		case 3: // simple packet
			if len(body) < 4 || len(fr.ifaces) == 0 {
				continue
			}
			orig := fr.bo.Uint32(body[0:])
			data := append([]byte(nil), body[4:]...)
			if int(orig) < len(data) {
				data = data[:orig]
			}
			return rawFrame{ts: time.Now(), link: fr.ifaces[0].link, data: data, origLen: int(orig), order: fr.bo, iface: fr.ifaces[0].name}, nil
		}
	}
}

func (fr *frameReader) walkOpts(opts []byte, fn func(code uint16, v []byte)) {
	for len(opts) >= 4 {
		code := fr.bo.Uint16(opts[0:])
		l := int(fr.bo.Uint16(opts[2:]))
		if code == 0 || 4+l > len(opts) {
			return
		}
		fn(code, opts[4:4+l])
		next := 4 + (l+3)/4*4
		if next > len(opts) {
			return
		}
		opts = opts[next:]
	}
}

// epbOpts reads standard epb_flags (direction) and Apple's process options.
func (fr *frameReader) epbOpts(f *rawFrame, opts []byte) {
	fr.walkOpts(opts, func(code uint16, v []byte) {
		if len(fr.Seen) < 64 {
			fr.Seen[fmt.Sprintf("epb opt 0x%x", code)]++
		}
		u32 := func() (uint32, bool) {
			if len(v) < 4 {
				return 0, false
			}
			return fr.bo.Uint32(v), true
		}
		switch code {
		case 2: // epb_flags: bits 0-1 direction
			if x, ok := u32(); ok {
				switch x & 3 {
				case 1:
					f.dir = "in"
				case 2:
					f.dir = "out"
				}
				f.meta = true
			}
		case 0x8001, 0x8003: // Apple: (effective) process info block index
			if x, ok := u32(); ok && int(x) < len(fr.pibs) {
				pe := fr.pibs[x]
				if code == 0x8001 {
					f.pid, f.comm = pe.pid, pe.name
				} else {
					f.epid, f.ecomm = pe.pid, pe.name
				}
				f.meta = true
			}
		case 0x8002: // Apple: service class
			if x, ok := u32(); ok {
				f.svc = x
			}
		}
	})
}

func (fr *frameReader) parseIfaceOpts(ifc *ngIface, opts []byte) {
	for len(opts) >= 4 {
		code := fr.bo.Uint16(opts[0:])
		l := int(fr.bo.Uint16(opts[2:]))
		if code == 0 || 4+l > len(opts) {
			return
		}
		v := opts[4 : 4+l]
		switch code {
		case 2:
			ifc.name = cstr(v)
		case 9:
			if l >= 1 {
				r := v[0]
				if r&0x80 != 0 {
					ifc.tsUnits = float64(uint64(1) << (r & 0x7f))
				} else {
					u := 1.0
					for i := 0; i < int(r); i++ {
						u *= 10
					}
					ifc.tsUnits = u
				}
			}
		}
		opts = opts[4+(l+3)/4*4:]
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
