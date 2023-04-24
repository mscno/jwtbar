package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func TestAMain(t *testing.T) {
	go func() {
		main()
	}()

	// wait for server to start
	time.Sleep(1 * time.Second)

	// get jwks
	resp, err := http.Get("http://localhost:8088/.well-known/jwks.json")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestJWKSRouter(t *testing.T) {

	r := NewEngine()
	r.GET("/.well-known/jwks.json", JwksHandler())
	pk, kid := getPrivateKey()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    "issuer1",
		Subject:   "sub1",
		Audience:  nil,
		ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Hour)},
		NotBefore: nil,
		IssuedAt:  nil,
		ID:        "",
	})
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(pk)
	require.NoError(t, err)
	fmt.Println(tokenString)
	go func() {
		err := r.Run(":8089")
		if err != nil {
			t.Fatalf("Failed to run server: %s", err)
		}
	}()
	jwks, err := keyfunc.Get("http://localhost:8089/.well-known/jwks.json", keyfunc.Options{})
	require.NoError(t, err)

	_, err = jwt.Parse(tokenString, jwks.Keyfunc, jwt.WithSubject("sub1"), jwt.WithIssuer("issuer1"), jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
}

func TestTokenSigner(t *testing.T) {

	r := NewEngine()
	registerRoutes(r)

	go func() {
		err := r.Run(":8090")
		if err != nil {
			t.Fatalf("Failed to run server: %s", err)
		}
	}()

	claims := jwt.RegisteredClaims{
		Issuer:  "issuer1",
		Subject: "sub1",
	}
	b := &bytes.Buffer{}
	err := json.NewEncoder(b).Encode(claims)
	require.NoError(t, err)
	res, err := http.Post("http://localhost:8090/oauth/token", "application/json", b)
	require.NoError(t, err)
	defer res.Body.Close()
	type token struct {
		AccessToken string `json:"access_token"`
	}
	var tokenRes token
	err = json.NewDecoder(res.Body).Decode(&tokenRes)
	require.NoError(t, err)

	jwks, err := keyfunc.Get("http://localhost:8090/.well-known/jwks.json", keyfunc.Options{})
	require.NoError(t, err)

	_, err = jwt.Parse(tokenRes.AccessToken, jwks.Keyfunc, jwt.WithSubject("sub1"), jwt.WithIssuer("issuer1"), jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
}
