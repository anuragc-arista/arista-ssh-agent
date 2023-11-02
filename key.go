package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// func LoadCACert(pemfile, keyfile string) (*x509.Certificate, ed25519.PrivateKey, error) {

// 	pembytes, err := os.ReadFile(pemfile)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	pemdata, _ := pem.Decode(pembytes)
// 	if pemdata == nil {
// 		return nil, nil, fmt.Errorf("invalid pem file")
// 	}

// 	if pemdata.Type != "CERTIFICATE" {
// 		return nil, nil, fmt.Errorf("invalid pem file")
// 	}

// 	cert, err := x509.ParseCertificate(pemdata.Bytes)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	keybytes, err := os.ReadFile(keyfile)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	keydata, _ := pem.Decode(keybytes)
// 	if keydata == nil {
// 		return nil, nil, fmt.Errorf("invalid key file")
// 	}

// 	if keydata.Type != "PRIVATE KEY" {
// 		return nil, nil, fmt.Errorf("invalid key file")
// 	}

// 	key, err := x509.ParsePKCS8PrivateKey(keydata.Bytes)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	return cert, key.(ed25519.PrivateKey), nil
// }

func GetCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter LDAP Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter LDAP Password: ")
	bytePassword, err := term.ReadPassword(0)
	if err != nil {
		slog.Error("Error reading password", "Error:", err)
	}
	fmt.Println("Password stored")
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
}

// https://developer.hashicorp.com/vault/api-docs/auth/ldap#login-with-ldap-user
func GetToken() (string, error) {

	type TokenInfo struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int    `json:"lease_duration"`
		Data          struct {
		} `json:"data"`
		WrapInfo any `json:"wrap_info"`
		Warnings any `json:"warnings"`
		Auth     struct {
			ClientToken      string   `json:"client_token"`
			Accessor         string   `json:"accessor"`
			Policies         []string `json:"policies"`
			TokenPolicies    []string `json:"token_policies"`
			IdentityPolicies []string `json:"identity_policies"`
			Metadata         struct {
				Username string `json:"username"`
			} `json:"metadata"`
			LeaseDuration  int    `json:"lease_duration"`
			Renewable      bool   `json:"renewable"`
			EntityID       string `json:"entity_id"`
			TokenType      string `json:"token_type"`
			Orphan         bool   `json:"orphan"`
			MfaRequirement any    `json:"mfa_requirement"`
			NumUses        int    `json:"num_uses"`
		} `json:"auth"`
	}

	username, password := GetCredentials()

	client := &http.Client{}
	data := map[string]string{"password": password}
	jsonData, _ := json.Marshal(data)
	url := "https://vault.aristanetworks.com:8200/v1/auth/ldap/login/"
	urlStr := fmt.Sprintf("%s%s", url, username)
	req, err := http.NewRequest("PUT", urlStr, bytes.NewBuffer(jsonData)) // Remove hardcoded username
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Request", "true")
	req.Header.Set("X-Vault-Namespace", "anet/engprod/")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var result TokenInfo
	if err := json.Unmarshal(bodyText, &result); err != nil { // Parse []byte to go struct pointer
		slog.Error("Can not unmarshal JSON", err)
	}

	return result.Auth.ClientToken, err
}

// https://developer.hashicorp.com/vault/api-docs/auth/token#renew-a-token
func TokenRenew(token string) (string, error) {
	type TokenRenewInfo struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int    `json:"lease_duration"`
		Data          any    `json:"data"`
		WrapInfo      any    `json:"wrap_info"`
		Warnings      any    `json:"warnings"`
		Auth          struct {
			ClientToken      string   `json:"client_token"`
			Accessor         string   `json:"accessor"`
			Policies         []string `json:"policies"`
			TokenPolicies    []string `json:"token_policies"`
			IdentityPolicies []string `json:"identity_policies"`
			Metadata         struct {
				Username string `json:"username"`
			} `json:"metadata"`
			LeaseDuration  int    `json:"lease_duration"`
			Renewable      bool   `json:"renewable"`
			EntityID       string `json:"entity_id"`
			TokenType      string `json:"token_type"`
			Orphan         bool   `json:"orphan"`
			MfaRequirement any    `json:"mfa_requirement"`
			NumUses        int    `json:"num_uses"`
		} `json:"auth"`
	}

	client := &http.Client{}
	var data = strings.NewReader(`{"increment":0}`)
	req, err := http.NewRequest("PUT", "https://vault.aristanetworks.com:8200/v1/auth/token/renew-self", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("X-Vault-Request", "true")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var result TokenRenewInfo
	if err := json.Unmarshal(bodyText, &result); err != nil { // Parse []byte to go struct pointer
		slog.Error("Can not unmarshal JSON", err)
	}

	return result.Auth.ClientToken, err
}

// https://developer.hashicorp.com/vault/api-docs/auth/token#lookup-a-token-self
func TokenLookup(token string) (int, error) {

	type TokenLookupInfo struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int    `json:"lease_duration"`
		Data          struct {
			Accessor                  string `json:"accessor"`
			CreationTime              int    `json:"creation_time"`
			CreationTTL               int    `json:"creation_ttl"`
			DisplayName               string `json:"display_name"`
			EntityID                  string `json:"entity_id"`
			ExpireTime                string `json:"expire_time"`
			ExplicitMaxTTL            int    `json:"explicit_max_ttl"`
			ExternalNamespacePolicies struct {
			} `json:"external_namespace_policies"`
			ID               string   `json:"id"`
			IdentityPolicies []string `json:"identity_policies"`
			IssueTime        string   `json:"issue_time"`
			Meta             struct {
				Username string `json:"username"`
			} `json:"meta"`
			NamespacePath string   `json:"namespace_path"`
			NumUses       int      `json:"num_uses"`
			Orphan        bool     `json:"orphan"`
			Path          string   `json:"path"`
			Policies      []string `json:"policies"`
			Renewable     bool     `json:"renewable"`
			TTL           int      `json:"ttl"`
			Type          string   `json:"type"`
		} `json:"data"`
		WrapInfo any `json:"wrap_info"`
		Warnings any `json:"warnings"`
		Auth     any `json:"auth"`
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://vault.aristanetworks.com:8200/v1/auth/token/lookup-self", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Request", "true")
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Printf("%s\n", bodyText)

	var result TokenLookupInfo
	if err := json.Unmarshal(bodyText, &result); err != nil { // Parse []byte to go struct pointer
		slog.Error("Can not unmarshal JSON", err)
	}

	return result.Data.TTL, err
}

func SignCert(sshpub ssh.PublicKey, token string) (string, error) {

	type SignCert struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int    `json:"lease_duration"`
		Data          struct {
			SerialNumber string `json:"serial_number"`
			SignedKey    string `json:"signed_key"`
		} `json:"data"`
		WrapInfo any `json:"wrap_info"`
		Warnings any `json:"warnings"`
		Auth     any `json:"auth"`
	}

	tokenMemAddr := &token

	// Here we check the existing token's ttl and renew if it has less that
	// 300 sec left but more that 60 sec. We will attempt to renew before each
	// request to sing the public key to obtain a certificate.
	tokenttl, err := TokenLookup(token)
	if err != nil {
		slog.Error("Error looking up token info", "Error:", err)
	}

	if tokenttl > 60 && tokenttl < 900 {
		slog.Info("Token needs renewal", "TTL", tokenttl)
		renewedtoken, err := TokenRenew(token)
		if err != nil {
			slog.Error("Error renewing token", "Error:", err)
			fmt.Println("Start login flow")
			newtoken, err := GetToken()
			if err != nil {
				slog.Error("Error getting new token", "Error:", err)
				os.Exit(1)
			}
			*tokenMemAddr = newtoken
			slog.Info("New token successfully obtained!")
		} else {
			*tokenMemAddr = renewedtoken
			slog.Info("Token successfully renewed!")
		}
	} else {
		slog.Info("Token TLL is greater that 300 sec", "TTL", tokenttl)
	}

	SshPub := string(ssh.MarshalAuthorizedKey(sshpub))
	data := map[string]string{"public_key": SshPub}
	jsonData, _ := json.Marshal(data)
	client := &http.Client{}
	url := "https://vault.aristanetworks.com:8200/v1/ssh/sign/user"
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Namespace", "anet/engprod/")
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Printf("%s\n", bodyText)

	var result SignCert
	if err := json.Unmarshal(bodyText, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}
	// fmt.Println(result.Data.SignedKey)
	SignedKey := result.Data.SignedKey
	return SignedKey, err
}

func GenerateSignedCert(username string, token string) (*ssh.Certificate, ed25519.PrivateKey, error) {

	// casigner, err := ssh.NewSignerFromKey(cakey)
	// if err != nil {
	// 	return nil, nil, err
	// }

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sshpub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	cert, err := SignCert(sshpub, token)
	if err != nil {
		slog.Error("Error signing ssh certificate with the CA", "Error:", err)
		return nil, nil, err
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		slog.Error("Error parsing ssh certificate", "Error:", err)
		return nil, nil, err
	}

	signedcert := pk.(*ssh.Certificate)

	return signedcert, priv, nil
}
