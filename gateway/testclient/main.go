package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "gateway address")
	classical := flag.Bool("classical", false, "offer only classical X25519")
	id := flag.String("id", "", "client id (letters, digits, hyphens only), sent as TLS server name")
	flag.Parse()

	// InsecureSkipVerify only because the demo cert is self-signed.
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, ServerName: *id}
	if *classical {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
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
