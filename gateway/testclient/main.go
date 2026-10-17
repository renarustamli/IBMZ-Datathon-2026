package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

// tunnel accepts plain TCP on local and carries each connection to the gateway over TLS,
// so a client that cannot do hybrid TLS itself (e.g. Python with OpenSSL 3.0) can use the gateway.
func tunnel(local, addr string, cfg *tls.Config) {
	ln, err := net.Listen("tcp", local)
	if err != nil {
		log.Fatal(err)
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
			conn, err := tls.Dial("tcp", addr, cfg)
			if err != nil {
				log.Printf("handshake failed: %v", err)
				return
			}
			defer conn.Close()
			log.Printf("connected, curve %v", conn.ConnectionState().CurveID)
			done := make(chan struct{}, 2)
			go func() { io.Copy(conn, c); done <- struct{}{} }()
			go func() { io.Copy(c, conn); done <- struct{}{} }()
			<-done
		}(c)
	}
}

func main() {
	addr := flag.String("addr", "localhost:8443", "gateway address")
	classical := flag.Bool("classical", false, "offer only classical X25519")
	id := flag.String("id", "", "client id (letters, digits, hyphens only), sent as TLS server name")
	local := flag.String("local", "", "run as a tunnel: listen for plain TCP here (e.g. 127.0.0.1:9100) and forward over TLS")
	flag.Parse()

	// InsecureSkipVerify only because the demo cert is self-signed.
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, ServerName: *id}
	if *classical {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	if *local != "" {
		tunnel(*local, *addr, cfg)
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
