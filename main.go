package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	user := os.Getenv("USER") // we should of course check the username from the UID
	// var token string
	// var role string

	var provisioner string
	flag.StringVar(&provisioner, "p", "google", "Default provisioner: google")
	flag.Parse()

	token, role, err := login(provisioner)
	if err != nil {
		slog.Error("Can not complete login flow", "error:", err)
		os.Exit(1)
	}

	slog.Info("Vault role", "role", role)
	slog.Info("Starting Arista SSH Agent")

	// token = loginOidc()

	os.Remove("agent.sock")

	socket, err := net.Listen("unix", "agent.sock")
	if err != nil {
		slog.Error("Listen", "error", err)
		os.Exit(1)
	}

	slog.Info("listening", "address", socket.Addr())

	for {
		conn, err := socket.Accept()
		if err != nil {
			slog.Error("Accept", "error", err)
			break
		}

		slog.Info("client connected", "addr", conn.RemoteAddr())

		go func() {
			defer conn.Close()

			session := Session{
				User: user,
			}

			cert, key, newtoken, err := GenerateSignedCert(session.User, token, provisioner, role)
			if err != nil {
				slog.Error("GenerateSignedCert", "error", err)
				return
			}
			token = newtoken
			slog.Debug("generated session cert and key", "cert", cert, "key", key)

			signer, err := ssh.NewSignerFromKey(key)
			if err != nil {
				slog.Error("NewSignerFromKey", "error", err)
				return
			}

			certsigner, err := ssh.NewCertSigner(cert, signer)
			if err != nil {
				slog.Error("NewCertSigner", "error", err)
				return
			}

			session.Certificate = cert
			session.Signer = certsigner

			if err := handle(conn, &session); err != nil {
				slog.Error("accept", "error", err)
				return
			}
		}()
	}
}

type Session struct {
	Request     io.Reader
	Response    io.Writer
	CACert      *x509.Certificate
	CAKey       ed25519.PrivateKey
	User        string
	Certificate *ssh.Certificate
	Signer      ssh.Signer
}

func handle(conn net.Conn, session *Session) error {

	for {
		var lenbuf [4]byte
		if _, err := io.ReadFull(conn, lenbuf[:]); err != nil {
			return err
		}

		msglen := binary.BigEndian.Uint32(lenbuf[:])
		if msglen == 0 {
			continue
		}

		msgbuf := make([]byte, msglen)
		if _, err := io.ReadFull(conn, msgbuf); err != nil {
			return err
		}

		msgtype := RequestCode(msgbuf[0])

		slog.Info("received message", "type", msgtype)

		handler := handlers[msgtype]
		if handler == nil {
			slog.Error("request type not implemented", "type", msgtype)
			writeUint32(conn, 1)
			writeUint8(conn, uint8(SSH_AGENT_FAILURE))
			continue
		}

		var resp bytes.Buffer

		session.Request = bytes.NewReader(msgbuf[1:])
		session.Response = &resp

		if err := handler(session); err != nil {
			slog.Error("handling message", "error", err)
			writeUint32(conn, 1)
			writeUint8(conn, uint8(SSH_AGENT_FAILURE))
			continue
		}

		writeUint32(conn, uint32(resp.Len()))
		if _, err := conn.Write(resp.Bytes()); err != nil {
			return err
		}
	}
}

func login(provisioner string) (token string, role string, err error) {
	slog.Info("Provisioner", "P", provisioner)
	switch provisioner {
	case "google":
		token, err := loginOidc()
		role = "user-google"
		return token, role, err
	case "ldap":
		token, err := loginLdap()
		role = "user"
		return token, role, err
	default:
		slog.Error("unsupported provisioner, options are -p google and -p ldap")
	}
	return "", "", errors.New("unsupported provisioner")
}
