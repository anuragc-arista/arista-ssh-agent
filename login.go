package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/cap/util"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

var token string

const (
	vaultAddress = "https://vault.aristanetworks.com:8200"
	redirectUri  = "http://localhost:8250/oidc/callback"
	port         = "8250"

	defaultRole       = "default"
	defaultNameSpace  = "anet/engprod"
	defaultMounthPath = "google"
)

func initVaultClient() *vault.Client {
	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(vaultAddress),
		vault.WithRequestTimeout(100*time.Second),
	)

	if err != nil {
		log.Fatal(err)
	}

	return client
}

func loginOidc() (clientToken string, err error) {
	cl := initVaultClient()

	authorizationURL, err := cl.Auth.JwtOidcRequestAuthorizationUrl(
		context.Background(),
		schema.JwtOidcRequestAuthorizationUrlRequest{
			RedirectUri: redirectUri,
			Role:        defaultRole,
		},
		vault.WithMountPath(defaultMounthPath),
		vault.WithNamespace(defaultNameSpace),
	)

	if err != nil {
		slog.Error("Error getting OIDC request authorization url", "error:", err)
		os.Exit(1)
	}
	authUrl := fmt.Sprintf("%s", authorizationURL.Data["auth_url"])

	clienToken, err := authorizeUser(redirectUri, authUrl)
	if err != nil {
		return "", err
	}
	return clienToken, nil
}

func codeHandler(server *http.Server, authorizationURL string) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// get the authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			slog.Error("Url parameter 'code' is missing")
			io.WriteString(w, "Error: could not find 'code' URL parameter\n")

			cleanup(server)
			return
		}

		// trade the authorization code for a vault client token
		clientToken, err := getClientToken(authorizationURL, code)
		if err != nil {
			slog.Error("Error getting vault client token", "error:", err)
			io.WriteString(w, "Error: could not retrieve vault token\n")

			cleanup(server)
			return
		}
		token = clientToken

		// return an indication of success to the caller
		io.WriteString(w, `
		<html>
			<body>
				<h1>Vault OIDC Login successful!</h1>
				<h2>You can close this window and return to the CLI.</h2>
			</body>
		</html>`)

		slog.Info("Successfully logged into Vault via OIDC.")

		cleanup(server)
	}
	return http.HandlerFunc(fn)
}

// AuthorizeUser implements the Vault OIDC OAuth2 flow.
func authorizeUser(redirectUri string, authorizationURL string) (clientToken string, err error) {
	// start a web server to listen on a callback URL
	mux := http.NewServeMux()
	server := &http.Server{Addr: redirectUri, Handler: mux}

	// define a handler that will get the authorization code, call the token endpoint, and close the HTTP server
	mux.Handle("/oidc/callback", codeHandler(server, authorizationURL))

	// parse the redirect URL for the port number
	u, err := url.Parse(redirectUri)
	if err != nil {
		slog.Error("Bad redirect URL", "error", err)
		return "", err
	}

	// set up a listener on the redirect port
	port := fmt.Sprintf(":%s", u.Port())
	l, err := net.Listen("tcp", port)
	if err != nil {
		slog.Error("Can't listen on redirect port", "port", port, "error", err)
		return "", err
	}

	// open a browser window to the authorizationURL
	slog.Info("Complete login via OIDC provider. Launching browser to:", "URL", authorizationURL)
	err = util.OpenURL(authorizationURL)
	if err != nil {
		slog.Error("Can't open browser", "URL", authorizationURL, "error", err)
		return "", err
	}
	slog.Info("Waiting for OIDC authentication to complete...")

	// start the blocking web server loop
	// this will exit when the handler gets fired and calls server.Close()
	server.Serve(l)

	return token, nil
}

// getIdToken trades the authorization code retrieved from the first OAuth2 leg for an ID token
func getClientToken(authorizationURL string, code string) (clientToken string, err error) {
	cl := initVaultClient()

	parsedUrl, err := url.Parse(authorizationURL)
	if err != nil {
		slog.Error("Error parsing auth_url", "error:", err)
		return "", err
	}
	nonce := parsedUrl.Query().Get("nonce")
	state := parsedUrl.Query().Get("state")

	// slog.Info("URL", "Nonce", nonce)
	// slog.Info("URL", "State", state)
	// slog.Info("Authorization Code", "CODE", code)

	authRsp, err := cl.Auth.JwtOidcCallback(
		context.Background(),
		nonce,
		code,
		state,
		vault.WithMountPath(defaultMounthPath),
		vault.WithNamespace(defaultNameSpace),
	)

	if err != nil {
		slog.Error("Error exchanging authorization code for Client Token", "error:", err)
		// close the HTTP server and return
		return "", err
	}

	// slog.Info("Vault Token", "TOKEN", authRsp.Auth.ClientToken)
	return authRsp.Auth.ClientToken, nil
}

// cleanup closes the HTTP server
func cleanup(server *http.Server) {
	// we run this as a goroutine so that this function falls through and
	// the socket to the browser gets flushed/closed before the server goes away
	go server.Close()
}
