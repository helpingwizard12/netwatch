// Netwatch: a local, browser-based view of every packet entering and leaving
// this Mac, grouped by app, connection, remote host and DNS lookup.
//
//	go build -o netwatch . && ./netwatch
//
// It runs `sudo tcpdump` for the capture (asks for your password once),
// decodes the stream itself, and serves the UI on http://127.0.0.1:8765.
package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

func main() {
	port := flag.Int("port", 8765, "port for the web interface (localhost only)")
	iface := flag.String("i", "any", "interface to capture on (any, en0, ...)")
	loop := flag.Bool("include-loopback", false, "also show traffic between programs on this Mac (127.0.0.1 / ::1)")
	filter := flag.String("filter", "", "extra tcpdump filter, e.g. 'not port 443'")
	save := flag.String("save", "", "also save the raw capture to this .pcap file (open it in Wireshark later)")
	read := flag.String("read", "", "replay a .pcap file instead of capturing live")
	noBrowser := flag.Bool("no-browser", false, "don't open the browser automatically")
	flag.Parse()

	sys := newSysInfo()
	st := newState(sys)

	bpf := buildFilter(*loop, *filter)
	st.Filter = bpf

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("cannot listen on port %d: %v (is netwatch already running? try -port 8766)", *port, err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", *port)

	var cmd *exec.Cmd
	if *read != "" {
		f, err := os.Open(*read)
		if err != nil {
			log.Fatal(err)
		}
		st.Source = "file " + *read
		go runReader(st, f, nil)
	} else {
		cmd, err = startTcpdump(st, *iface, bpf, *save)
		if err != nil {
			log.Fatal(err)
		}
	}

	srv := &http.Server{Handler: routes(st, *port), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	fmt.Printf("\n  Netwatch is running →  %s\n  Press Ctrl+C to stop.\n\n", url)
	if !*noBrowser {
		_ = exec.Command("open", url).Start()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("\nStopping…")
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	_ = srv.Close()
}

func buildFilter(loop bool, extra string) string {
	var parts []string
	if !loop {
		parts = append(parts, "not host 127.0.0.1 and not host ::1")
	}
	if strings.TrimSpace(extra) != "" {
		parts = append(parts, "("+extra+")")
	}
	return strings.Join(parts, " and ")
}

func startTcpdump(st *State, iface, bpf, save string) (*exec.Cmd, error) {
	args := []string{"tcpdump", "-i", iface, "-n", "-U", "-s", "2048", "-w", "-"}
	if bpf != "" {
		args = append(args, bpf)
	}
	if os.Geteuid() != 0 {
		fmt.Println("Netwatch needs admin rights to capture packets.")
		fmt.Println("macOS will ask for your login password (it is passed to sudo, not stored).")
		v := exec.Command("sudo", "-v")
		v.Stdin, v.Stdout, v.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := v.Run(); err != nil {
			return nil, fmt.Errorf("sudo failed: %w", err)
		}
		args = append([]string{"sudo"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start tcpdump: %w", err)
	}
	st.Source = "live capture on " + iface
	st.setStatus("starting tcpdump…", "")

	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := strings.TrimPrefix(sc.Text(), "tcpdump: ")
			switch {
			case strings.HasPrefix(line, "listening on"):
				st.setStatus(line, "")
			case strings.Contains(line, "data link type"), strings.Contains(line, "verbose output"):
			default:
				st.setStatus("", line)
				fmt.Fprintln(os.Stderr, "tcpdump:", line)
			}
		}
	}()

	var w io.Writer
	if save != "" {
		f, err := os.Create(save)
		if err != nil {
			return nil, err
		}
		w = f
		fmt.Println("Saving raw capture to", save)
	}
	go runReader(st, stdout, w)
	go func() {
		err := cmd.Wait()
		st.mu.Lock()
		st.Capturing = false
		if err != nil && st.Error == "" {
			st.Error = "tcpdump exited: " + err.Error()
		}
		st.Status = "capture stopped"
		st.mu.Unlock()
	}()
	return cmd, nil
}

func runReader(st *State, src io.Reader, save io.Writer) {
	if save != nil {
		src = io.TeeReader(src, save)
	}
	fr, err := newFrameReader(src)
	if err != nil {
		st.setStatus("capture stopped", err.Error())
		return
	}
	st.mu.Lock()
	st.Capturing = true
	if st.Status == "" || strings.HasPrefix(st.Status, "starting") {
		st.Status = "capturing"
	}
	st.mu.Unlock()
	for {
		f, err := fr.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				st.setStatus("", "read error: "+err.Error())
			}
			st.mu.Lock()
			st.Capturing = false
			if strings.HasPrefix(st.Source, "file") {
				st.Status = "finished reading file"
			}
			st.mu.Unlock()
			return
		}
		if len(fr.Seen) > 0 {
			st.mu.Lock()
			st.Seen = fr.Seen
			st.mu.Unlock()
		}
		p := decodeFrame(f)
		st.ingest(p)
	}
}

func routes(st *State, port int) http.Handler {
	allowed := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", port): true,
		fmt.Sprintf("localhost:%d", port): true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		writeJSON(w, st.snapshot(since))
	})
	mux.HandleFunc("GET /api/packet", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		p, ok := st.packet(id)
		if !ok {
			http.Error(w, "packet no longer in memory", http.StatusNotFound)
			return
		}
		writeJSON(w, p)
	})
	mux.HandleFunc("POST /api/reset", func(w http.ResponseWriter, r *http.Request) {
		st.Reset()
		writeJSON(w, map[string]bool{"ok": true})
	})
	// Only answer requests addressed to localhost (blocks DNS-rebinding).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.Host] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
