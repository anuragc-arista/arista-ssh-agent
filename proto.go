package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/ssh"
)

func writeUint32(w io.Writer, v uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func writeUint8(w io.Writer, v uint8) error {
	var buf [1]byte
	buf[0] = v
	_, err := w.Write(buf[:])
	return err
}

func writeBuf(w io.Writer, buf []byte) error {
	if err := writeUint32(w, uint32(len(buf))); err != nil {
		return err
	}
	if _, err := w.Write(buf); err != nil {
		return err
	}
	return nil
}

func writeStruct(w io.Writer, v any) error {
	return writeBuf(w, ssh.Marshal(v))
}

func readUint8(r io.Reader) (uint8, error) {
	var buf [1]byte
	_, err := r.Read(buf[:])
	return buf[0], err
}

func readBool(r io.Reader) (bool, error) {
	v, err := readUint8(r)
	return v == 1, err
}

func readUint32(r io.Reader) (uint32, error) {
	var buf [4]byte
	_, err := io.ReadFull(r, buf[:])
	return binary.BigEndian.Uint32(buf[:]), err
}

func readBuf(r io.Reader) ([]byte, error) {
	l, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readString(r io.Reader) (string, error) {
	buf, err := readBuf(r)
	return string(buf), err
}

type Handler func(*Session) error

var handlers = map[RequestCode]Handler{
	SSH_AGENTC_SIGN_REQUEST:       signRequest,
	SSH_AGENTC_REQUEST_IDENTITIES: requestIdentities,
	SSH_AGENTC_EXTENSION:          handleExtension,
}

func signRequest(s *Session) error {

	if s.Certificate == nil {
		return fmt.Errorf("ssh client did not bind the current session; it must send a session-bind@openssh.com request first")
	}

	pubkeybytes, err := readBuf(s.Request)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	if !bytes.Equal(pubkeybytes, s.Certificate.Marshal()) {
		return fmt.Errorf("signature request done with unknown public key")
	}

	nonce, err := readBuf(s.Request)
	if err != nil {
		return fmt.Errorf("reading nonce: %w", err)
	}

	flags, err := readUint32(s.Request)
	if err != nil {
		return fmt.Errorf("reading flags: %w", err)
	}

	pubkey, err := ssh.ParsePublicKey(pubkeybytes)
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}

	slog.Info("signature request", "key", string(ssh.MarshalAuthorizedKey(pubkey)), "flags", flags)

	sig, err := s.Signer.Sign(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("signing nonce: %w", err)
	}

	if err := writeUint8(s.Response, uint8(SSH_AGENT_SIGN_RESPONSE)); err != nil {
		return err
	}
	if err := writeStruct(s.Response, sig); err != nil {
		return err
	}

	return nil
}

func requestIdentities(s *Session) error {

	writeUint8(s.Response, uint8(SSH_AGENT_IDENTITIES_ANSWER))

	if s.Certificate != nil {
		// We have 1 key
		writeUint32(s.Response, 1)

		certdata := s.Certificate.Marshal()

		writeUint32(s.Response, uint32(len(certdata)))
		if _, err := s.Response.Write(certdata); err != nil {
			return err
		}

		comment := "snaipe@arista.com"

		writeUint32(s.Response, uint32(len(comment)))
		if _, err := s.Response.Write([]byte(comment)); err != nil {
			return err
		}
	} else {
		writeUint32(s.Response, 0)
	}

	return nil
}

var extensionHandlers = map[string]Handler{
	"session-bind@openssh.com": bindSession,
}

func handleExtension(s *Session) error {
	ext, err := readString(s.Request)
	if err != nil {
		return err
	}

	handler := extensionHandlers[ext]
	if handler == nil {
		return fmt.Errorf("no handler for extension %s", ext)
	}
	return handler(s)
}

func bindSession(s *Session) error {

	// This session binding extension is used by openssh to communicate
	// host-related information to the agent. We could use this in principle
	// to validate further whether the requesting user is allowed to connect
	// to this specific host, but we're not using this for now.
	//
	// More info about the extension, rationale, and other work here:
	// https://www.openssh.com/agent-restrict.html

	hostkeybytes, err := readBuf(s.Request)
	if err != nil {
		return fmt.Errorf("reading host key: %w", err)
	}

	hostkey, err := ssh.ParsePublicKey(hostkeybytes)
	if err != nil {
		return fmt.Errorf("parsing host key: %w", err)
	}

	sessionID, err := readBuf(s.Request)
	if err != nil {
		return fmt.Errorf("reading session ID: %w", err)
	}

	hostKeySignatureBytes, err := readBuf(s.Request)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	isForwarding, err := readBool(s.Request)
	if err != nil {
		return fmt.Errorf("reading is-forwarding: %w", err)
	}

	var hostKeySignature ssh.Signature
	if err := ssh.Unmarshal(hostKeySignatureBytes, &hostKeySignature); err != nil {
		return fmt.Errorf("parsing host key signature: %w", err)
	}

	slog.Info("connecting",
		"hostkey", string(ssh.MarshalAuthorizedKey(hostkey)),
		"session", base64.StdEncoding.EncodeToString(sessionID),
		"hostkey-signature-type", hostKeySignature.Format,
		"hostkey-signature", base64.StdEncoding.EncodeToString(hostKeySignature.Blob),
		"is-forwarding", isForwarding)

	// This is where the client would normally generate and send the
	// session certificate to a signing server

	cert, key, err := GenerateSignedCert(s.User, s.CACert, s.CAKey)
	if err != nil {
		slog.Error("GenerateSignedCert", "error", err)
	}

	slog.Debug("generated session cert and key", "cert", cert, "key", key)

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		slog.Error("NewSignerFromKey", "error", err)
	}

	certsigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		slog.Error("NewCertSigner", "error", err)
	}

	s.Certificate = cert
	s.Signer = certsigner

	writeUint8(s.Response, uint8(SSH_AGENT_SUCCESS))
	return nil
}
