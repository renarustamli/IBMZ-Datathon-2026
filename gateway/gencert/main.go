// gencert writes a self-signed certificate and key for the gateway.
//
//	-pq   : ML-DSA-65 certificate (post-quantum signature, FIPS 204)
//	default: ECDSA P-256 certificate (classical)
//
// Standard library only. The ML-DSA option makes the certificate's signature
// quantum-safe; ML-KEM in the gateway already makes the key exchange quantum-safe.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	pq := flag.Bool("pq", false, "ML-DSA-65 certificate instead of classical ECDSA")
	cn := flag.String("cn", "localhost", "certificate common name")
	certOut := flag.String("cert", "cert.pem", "certificate output file")
	keyOut := flag.String("key", "key.pem", "private key output file")
	days := flag.Int("days", 7, "validity in days")
	flag.Parse()

	var signer crypto.Signer
	var err error
	label := "ECDSA P-256 (classical)"
	if *pq {
		signer, err = mldsa.GenerateKey(mldsa.MLDSA65())
		label = "ML-DSA-65 (post-quantum, FIPS 204)"
	} else {
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		log.Fatalf("key generation: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: *cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, *days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{*cn},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}

	certFile, err := os.Create(*certOut)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certFile.Close()

	keyFile, err := os.OpenFile(*keyOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()

	// Confirm the certificate parses and report its signature algorithm.
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatalf("re-parse: %v", err)
	}
	log.Printf("wrote %s and %s", *certOut, *keyOut)
	log.Printf("certificate: %s, signature algorithm %s", label, parsed.SignatureAlgorithm)
}
