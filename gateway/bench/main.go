// Benchmark: classical X25519 vs hybrid X25519MLKEM768 handshakes through the gateway.
//
// The bench runs its own backend (on -backend-listen) that sends N bytes on request.
// Start a separate gateway in legacy mode pointing at it, so bench notes stay out of D's log:
//
//	./gateway -mode legacy -listen 127.0.0.1:8444 -backend 127.0.0.1:9100 -notes logs/bench.jsonl
//	go run ./bench -addr 127.0.0.1:8444 -n 500
package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// countConn counts bytes on the wire (TLS records), so handshake sizes are measured, not assumed.
type countConn struct {
	net.Conn
	sent, recv int
}

func (c *countConn) Write(b []byte) (int, error) { n, err := c.Conn.Write(b); c.sent += n; return n, err }
func (c *countConn) Read(b []byte) (int, error)  { n, err := c.Conn.Read(b); c.recv += n; return n, err }

type mode struct {
	name  string
	curve tls.CurveID
}

var modes = []mode{{"classical X25519", tls.X25519}, {"hybrid X25519MLKEM768", tls.X25519MLKEM768}}

func clientConfig(m mode) *tls.Config {
	// InsecureSkipVerify only because the demo cert is self-signed.
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{m.curve}, ServerName: "bench-client"}
}

// handshake dials the gateway and completes one TLS handshake.
func handshake(addr string, m mode) (time.Duration, int, int, *tls.Conn, error) {
	start := time.Now()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	cc := &countConn{Conn: raw}
	conn := tls.Client(cc, clientConfig(m))
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return 0, 0, 0, nil, err
	}
	d := time.Since(start)
	if conn.ConnectionState().CurveID != m.curve {
		conn.Close()
		return 0, 0, 0, nil, fmt.Errorf("negotiated %v, wanted %v", conn.ConnectionState().CurveID, m.curve)
	}
	return d, cc.sent, cc.recv, conn, nil
}

// backend: reads an 8-byte length, then sends that many bytes and closes.
func backend(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			var hdr [8]byte
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				return
			}
			for left := int64(binary.BigEndian.Uint64(hdr[:])); left > 0; {
				n := int64(len(buf))
				if left < n {
					n = left
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
				left -= n
			}
		}(c)
	}
}

func throughput(addr string, m mode, size int64) (float64, error) {
	_, _, _, conn, err := handshake(addr, m)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(size))
	start := time.Now()
	if _, err := conn.Write(hdr[:]); err != nil {
		return 0, err
	}
	n, err := io.Copy(io.Discard, conn)
	if err != nil {
		return 0, err
	}
	if n != size {
		return 0, fmt.Errorf("got %d bytes, want %d", n, size)
	}
	return float64(n) / time.Since(start).Seconds() / 1e6, nil
}

func stats(ds []time.Duration) (mean, p50, p95 float64) {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum time.Duration
	for _, d := range s {
		sum += d
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	return ms(sum / time.Duration(len(s))), ms(s[len(s)/2]), ms(s[(len(s)*95+99)/100-1])
}

// timeOp returns the mean time of f in microseconds.
func timeOp(iters int, f func()) float64 {
	start := time.Now()
	for i := 0; i < iters; i++ {
		f()
	}
	return float64(time.Since(start).Nanoseconds()) / float64(iters) / 1000
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8444", "gateway address (legacy mode)")
	backendListen := flag.String("backend-listen", "127.0.0.1:9100", "where the bench backend listens")
	n := flag.Int("n", 500, "handshakes per mode")
	mb := flag.Int("mb", 100, "MB per throughput run")
	runs := flag.Int("runs", 5, "throughput runs per mode")
	out := flag.String("out", "bench", "output directory")
	flag.Parse()

	go backend(*backendListen)
	time.Sleep(200 * time.Millisecond)

	// Sizes straight from crypto/mlkem and crypto/ecdh.
	dk, _ := mlkem.GenerateKey768()
	ek := dk.EncapsulationKey()
	_, ct := ek.Encapsulate()
	xk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ekLen, ctLen, xLen := len(ek.Bytes()), len(ct), len(xk.PublicKey().Bytes())

	// Raw key-exchange primitive cost (one side's work), no network.
	const it = 2000
	xPeer, _ := ecdh.X25519().GenerateKey(rand.Reader)
	tXGen := timeOp(it, func() { ecdh.X25519().GenerateKey(rand.Reader) })
	tXDH := timeOp(it, func() { xk.ECDH(xPeer.PublicKey()) })
	tKGen := timeOp(it, func() { mlkem.GenerateKey768() })
	tEnc := timeOp(it, func() { ek.Encapsulate() })
	tDec := timeOp(it, func() { dk.Decapsulate(ct) })

	// Warm up, then alternate modes so drift on the shared machine hits both equally.
	for i := 0; i < 20; i++ {
		for _, m := range modes {
			if _, _, _, c, err := handshake(*addr, m); err != nil {
				log.Fatalf("warm-up %s: %v (is the gateway running in legacy mode on %s?)", m.name, err, *addr)
			} else {
				c.Close()
			}
		}
	}
	lat := map[string][]time.Duration{}
	sent, recv := map[string]int{}, map[string]int{}
	os.MkdirAll(*out, 0o755)
	raw, err := os.Create(*out + "/handshakes.csv")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(raw, "mode,i,latency_ms,client_bytes_sent,client_bytes_recv")
	for i := 0; i < *n; i++ {
		for _, m := range modes {
			d, s, r, c, err := handshake(*addr, m)
			if err != nil {
				log.Fatalf("%s: %v", m.name, err)
			}
			c.Close()
			lat[m.name] = append(lat[m.name], d)
			sent[m.name], recv[m.name] = s, r
			fmt.Fprintf(raw, "%s,%d,%.3f,%d,%d\n", m.name, i, float64(d.Microseconds())/1000, s, r)
		}
	}
	raw.Close()

	tput := map[string]float64{}
	for _, m := range modes {
		var sum float64
		for r := 0; r < *runs; r++ {
			v, err := throughput(*addr, m, int64(*mb)<<20)
			if err != nil {
				log.Fatalf("throughput %s: %v", m.name, err)
			}
			sum += v
		}
		tput[m.name] = sum / float64(*runs)
	}

	csv, err := os.Create(*out + "/results.csv")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(csv, "mode,handshakes,mean_ms,p50_ms,p95_ms,client_handshake_bytes_sent,client_handshake_bytes_recv,throughput_MBps")
	var md strings.Builder
	host, _ := os.Hostname()
	fmt.Fprintf(&md, "# Gateway benchmarks\n\nMeasured %s on `%s` (%s/%s, %d CPUs, %s). Client, gateway (legacy mode) and backend all on the same host over loopback, so latency is CPU cost plus loopback, not real network.\n\n",
		time.Now().UTC().Format("2006-01-02 15:04 MST"), host, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	fmt.Fprintf(&md, "## Handshake latency (%d handshakes per mode, modes alternated, 20 warm-ups each discarded)\n\n", *n)
	md.WriteString("| Key exchange | mean (ms) | p50 (ms) | p95 (ms) | client bytes sent | client bytes received | throughput (MB/s) |\n|---|---|---|---|---|---|---|\n")
	for _, m := range modes {
		mean, p50, p95 := stats(lat[m.name])
		fmt.Fprintf(csv, "%s,%d,%.3f,%.3f,%.3f,%d,%d,%.1f\n", m.name, *n, mean, p50, p95, sent[m.name], recv[m.name], tput[m.name])
		fmt.Fprintf(&md, "| %s | %.3f | %.3f | %.3f | %d | %d | %.1f |\n", m.name, mean, p50, p95, sent[m.name], recv[m.name], tput[m.name])
	}
	csv.Close()
	fmt.Fprintf(&md, "\nThroughput: mean of %d downloads of %d MB each through the gateway. The bulk cipher is TLS_AES_128_GCM_SHA256 in both modes (Go picks it; the key exchange only changes the handshake), so throughput should be about the same.\n\n", *runs, *mb)
	fmt.Fprintf(&md, "## Key sizes (read from crypto/mlkem and crypto/ecdh)\n\n| Item | bytes |\n|---|---|\n| X25519 public key | %d |\n| ML-KEM-768 encapsulation key | %d |\n| ML-KEM-768 ciphertext | %d |\n| Hybrid client key share (ML-KEM ek + X25519) | %d |\n| Hybrid server key share (ML-KEM ct + X25519) | %d |\n\n",
		xLen, ekLen, ctLen, ekLen+xLen, ctLen+xLen)
	fmt.Fprintf(&md, "## Key-exchange primitives (mean of %d ops, microseconds)\n\n| Operation | µs |\n|---|---|\n| X25519 keygen | %.1f |\n| X25519 shared secret | %.1f |\n| ML-KEM-768 keygen | %.1f |\n| ML-KEM-768 encapsulate | %.1f |\n| ML-KEM-768 decapsulate | %.1f |\n\n",
		it, tXGen, tXDH, tKGen, tEnc, tDec)
	md.WriteString("Raw per-handshake data: `handshakes.csv`. Summary: `results.csv`. Certificates are classical ECDSA in both modes.\n")
	if err := os.WriteFile(*out+"/benchmarks.md", []byte(md.String()), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Print(md.String())
}
