package main

import (
	"context"
	"github.com/MicahParks/jwkset"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"log"
	"net/http"
	"time"
)

func NewEngine() *gin.Engine {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	return r
}

func JwksHandler() gin.HandlerFunc {
	ctx := context.Background()
	jwkSet := jwkset.NewMemory[any]()

	_, privateKid := getPrivateKey()
	publicKey, _ := getPublicKey()

	err := jwkSet.Store.WriteKey(ctx, jwkset.NewKey[any](publicKey, privateKid))
	if err != nil {
		log.Fatalf("Failed to store RSA publicKey: %s", err)
	}

	response, err := jwkSet.JSONPublic(ctx)
	if err != nil {
		log.Fatalf("Failed to get JWK Set: %s", err)
	}

	return func(c *gin.Context) {
		c.JSON(http.StatusOK, response)
	}
}

func TokenSignerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var claims jwt.MapClaims
		err := c.BindJSON(&claims)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// if no exp is set, set it to 1 hour
		if _, ok := claims["exp"]; !ok {
			claims["exp"] = time.Now().Add(time.Hour).Unix()
		}

		if _, ok := claims["iat"]; !ok {
			claims["iat"] = time.Now().Unix()
		}

		if _, ok := claims["nbf"]; !ok {
			claims["nbf"] = time.Now().Unix()
		}

		if _, ok := claims["iss"]; !ok {
			claims["iss"] = "https://jwt.bar"
		}

		if _, ok := claims["aud"]; !ok {
			claims["aud"] = "https://jwt.bar"
		}

		if _, ok := claims["sub"]; !ok {
			claims["sub"] = "https://jwt.bar"
		}

		if _, ok := claims["jti"]; !ok {
			claims["jti"] = uuid.NewString()
		}

		pk, kid := getPrivateKey()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		tokenString, err := token.SignedString(pk)

		c.JSON(http.StatusOK, gin.H{"access_token": tokenString})
	}
}
