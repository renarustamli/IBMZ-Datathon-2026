package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// frame matches the recording format of C's legacy server, so C's attacker can read it.
type frame struct {
	Dir   string            `json:"dir"`
	Frame map[string]string `json:"frame"`
}

// recConn records the raw bytes on the wire between client and gateway: TLS records only,
// which is all an eavesdropper harvesting traffic would get.
type recConn struct {
	net.Conn
	mu     sync.Mutex
	frames []frame
}

func (r *recConn) add(dir string, b []byte) {
	r.mu.Lock()
	r.frames = append(r.frames, frame{dir, map[string]string{"type": "tls-record", "hex": hex.EncodeToString(b)}})
	r.mu.Unlock()
}

func (r *recConn) Write(b []byte) (int, error) {
	n, err := r.Conn.Write(b)
	r.add("client->server", b[:n])
	return n, err
}

func (r *recConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.add("server->client", b[:n])
	}
	return n, err
}

var (
	recMu  sync.Mutex
	recNum int
)

func saveRecording(dir string, frames []frame) {
	recMu.Lock()
	defer recMu.Unlock()
	if recNum == 0 {
		old, _ := filepath.Glob(filepath.Join(dir, "session_*.json"))
		recNum = len(old)
	}
	recNum++
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // keep "->" readable
	enc.SetIndent("", "  ")
	enc.Encode(frames)
	name := filepath.Join(dir, fmt.Sprintf("session_%03d.json", recNum))
	if err := os.WriteFile(name, b.Bytes(), 0o644); err != nil {
		log.Print(err)
		return
	}
	log.Printf("recorded %d wire chunks to %s", len(frames), name)
}

// tunnel accepts plain TCP on local and carries each connection to the gateway over TLS,
// so a client that cannot do hybrid TLS itself (e.g. Python with OpenSSL 3.0) can use the gateway.
// With record set, the encrypted client<->gateway bytes of each connection are saved there.
func tunnel(local, addr, record string, cfg *tls.Config) {
	ln, err := net.Listen("tcp", local)
	if err != nil {
		log.Fatal(err)
	}
	if record != "" {
		os.MkdirAll(record, 0o755)
	}
	cfg = cfg.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName, _, _ = net.SplitHostPort(addr) // same default tls.Dial uses
	}
	log.Printf("tunnel %s -> %s (client id %q)", local, addr, cfg.ServerName)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				log.Print(err)
				return
			}
			rec := &recConn{Conn: raw}
			if record != "" {
				defer func() { saveRecording(record, rec.frames) }()
			}
			conn := tls.Client(rec, cfg)
			defer conn.Close()
			if err := conn.Handshake(); err != nil {
				log.Printf("handshake failed: %v", err)
				return
			}
			log.Printf("connected, curve %v", conn.ConnectionState().CurveID)
			done := make(chan struct{}, 2)
			go func() { io.Copy(conn, c); done <- struct{}{} }()
			go func() { io.Copy(c, conn); done <- struct{}{} }()
			<-done
			c.Close()
			conn.Close()
			<-done
		}(c)
	}
}

func main() {
	addr := flag.String("addr", "localhost:8443", "gateway address")
	classical := flag.Bool("classical", false, "offer only classical X25519")
	id := flag.String("id", "", "client id (letters, digits, hyphens only), sent as TLS server name")
	local := flag.String("local", "", "run as a tunnel: listen for plain TCP here (e.g. 127.0.0.1:9100) and forward over TLS")
	record := flag.String("record", "", "with -local: save each connection's encrypted wire bytes as session_NNN.json in this folder")
	flag.Parse()

	// InsecureSkipVerify only because the demo cert is self-signed.
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, ServerName: *id}
	if *classical {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	if *local != "" {
		tunnel(*local, *addr, *record, cfg)
		return
	}
	conn, err := tls.Dial("tcp", *addr, cfg)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	defer conn.Close()

	st := conn.ConnectionState()
	if st.CurveID == tls.X25519MLKEM768 {
		fmt.Println("connected with hybrid post-quantum key exchange (X25519MLKEM768)")
	} else {
		fmt.Println("connected with classical key exchange, curve id:", st.CurveID)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	b, _ := io.ReadAll(conn)
	fmt.Println(len(b), "bytes received")
}
