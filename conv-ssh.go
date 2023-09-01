//go:build tool
// +build tool

package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	pembytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("unable to read certificate file: %v", err)
	}

	pemdata, _ := pem.Decode(pembytes)
	if pemdata == nil {
		log.Fatalf("invalid pem file")
	}

	if pemdata.Type != "CERTIFICATE" {
		log.Fatalf("invalid pem file")
	}

	cert, err := x509.ParseCertificate(pemdata.Bytes)
	if err != nil {
		log.Fatalf("unable to parse certificate file: %v", err)
	}

	sshkey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		log.Fatalf("unable to convert public key to ssh: %v", err)
	}

	b64key := base64.StdEncoding.EncodeToString(sshkey.Marshal())

	fmt.Printf("%s %s host-ca\n", sshkey.Type(), b64key)
}
