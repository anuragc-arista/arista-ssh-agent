package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
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
func loginLdap(vaultConfig *Vault) error {

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
	req, err := http.NewRequest("PUT", urlStr, bytes.NewBuffer(jsonData))
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

	if resp.StatusCode != 200 {
		slog.Error("Invalid token request",
			"Status Code", resp.StatusCode,
			"Body", bodyText,
			"Error", err)
		return errors.New("invalid token request")
	} else {
		slog.Info("Vault token obtained", "Status Code:", resp.StatusCode)
	}

	var result TokenInfo
	if err := json.Unmarshal(bodyText, &result); err != nil {
		slog.Error("Can not unmarshal JSON", err)
	}
	vaultConfig.Token = &result.Auth.ClientToken

	return err
}

// https://developer.hashicorp.com/vault/api-docs/auth/token#renew-a-token
func TokenRenew(vaultConfig *Vault) error {

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
	url := "https://vault.aristanetworks.com:8200/v1/auth/token/renew-self"
	req, err := http.NewRequest("PUT", url, data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", *vaultConfig.Token)
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

	if resp.StatusCode != 200 {
		slog.Error("Token renewal rejected",
			"Status Code", resp.StatusCode,
			"Body", bodyText,
			"Error", err)
		return errors.New("invalid token")
	} else {
		slog.Info("Token renewal", "Status Code:", resp.StatusCode)
	}

	var result TokenRenewInfo
	if err := json.Unmarshal(bodyText, &result); err != nil {
		slog.Error("Can not unmarshal JSON", err)
	}
	vaultConfig.Token = &result.Auth.ClientToken

	return err
}

// https://developer.hashicorp.com/vault/api-docs/auth/token#lookup-a-token-self
func TokenLookup(token *string) (int, error) {

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
	url := "https://vault.aristanetworks.com:8200/v1/auth/token/lookup-self"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Request", "true")
	req.Header.Set("X-Vault-Token", *token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		slog.Error("Token lookup rejected",
			"Status Code", resp.StatusCode,
			"Body", bodyText,
			"Error", err)
		return 0, errors.New("invalid token")
	} else {
		slog.Info("Token lookup success", "status code", resp.StatusCode)
	}

	var result TokenLookupInfo
	if err := json.Unmarshal(bodyText, &result); err != nil {
		slog.Error("Can not unmarshal JSON", err)
	}

	return result.Data.TTL, err
}

func SignCert(sshpub ssh.PublicKey, vaultConfig *Vault) (SignedKey string, err error) {

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

	tokenttl, err := TokenLookup(vaultConfig.Token)
	if err != nil {
		slog.Error("Can not get token ttl", "Error:", err)
	}

	if tokenttl < 3000 || canConnectToPort() {
		slog.Info("Token needs renewal", "ttl", tokenttl)
		err = TokenRenew(vaultConfig)
		if err != nil {
			slog.Error("Can not renew token", "error:", err)
			err = login(vaultConfig)
			if err != nil {
				slog.Error("Can not complete login flow", "error:", err)
				os.Exit(1)
			}
			slog.Info("New token successfully obtained!", "Token", *vaultConfig.Token)
		} else {
			slog.Info("Token successfully renewed!", "token", *vaultConfig.Token)
		}
	} else {
		slog.Info("Token does not need renewal", "ttl", tokenttl)
	}

	data := map[string]string{"public_key": string(ssh.MarshalAuthorizedKey(sshpub))}
	jsonData, _ := json.Marshal(data)

	client := &http.Client{}

	url := fmt.Sprintf(
		"https://vault.aristanetworks.com:8200/v1/%s/sign/%s",
		vaultConfig.SecretEngine,
		vaultConfig.Role)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Namespace", "anet/engprod/")
	req.Header.Set("X-Vault-Token", *vaultConfig.Token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		slog.Error("Unable to sign public ssh key with CA",
			"Status Code", resp.StatusCode,
			"Body", bodyText,
			"Error", err)
		return "", errors.New("error signing public ssh key")
	} else {
		slog.Info("Signed ssh public key", "status code", resp.StatusCode)
	}

	var result SignCert
	if err := json.Unmarshal(bodyText, &result); err != nil {
		fmt.Println("Can not unmarshal JSON")
	}
	slog.Info("ssh certificate", "key", result.Data.SignedKey)

	return result.Data.SignedKey, err
}

func GenerateSignedCert(username string, vaultConfig *Vault) (*ssh.Certificate, ed25519.PrivateKey, error) {

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sshpub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	cert, err := SignCert(sshpub, vaultConfig)
	if err != nil {
		return nil, nil, err
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		slog.Error("Error parsing ssh certificate", "Error:", err)
		return nil, nil, err
	}

	return pk.(*ssh.Certificate), priv, nil
}
