package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func LoadCACert(pemfile, keyfile string) (*x509.Certificate, ed25519.PrivateKey, error) {

	pembytes, err := os.ReadFile(pemfile)
	if err != nil {
		return nil, nil, err
	}

	pemdata, _ := pem.Decode(pembytes)
	if pemdata == nil {
		return nil, nil, fmt.Errorf("invalid pem file")
	}

	if pemdata.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid pem file")
	}

	cert, err := x509.ParseCertificate(pemdata.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keybytes, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, nil, err
	}

	keydata, _ := pem.Decode(keybytes)
	if keydata == nil {
		return nil, nil, fmt.Errorf("invalid key file")
	}

	if keydata.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("invalid key file")
	}

	key, err := x509.ParsePKCS8PrivateKey(keydata.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key.(ed25519.PrivateKey), nil
}

func GenerateSignedCert(username string, ca *x509.Certificate, cakey ed25519.PrivateKey) (*ssh.Certificate, ed25519.PrivateKey, error) {

	casigner, err := ssh.NewSignerFromKey(cakey)
	if err != nil {
		return nil, nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sshpub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	cert := ssh.Certificate{
		Key:         sshpub,
		CertType:    1,
		ValidAfter:  uint64(time.Now().Unix()),
		ValidBefore: uint64(time.Now().Add(24 * time.Hour).Unix()),
		KeyId:       username + "@arista.com",
		ValidPrincipals: []string{
			username,
			"arastra",
		},
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, casigner); err != nil {
		return nil, nil, err
	}

	return &cert, priv, nil
}
