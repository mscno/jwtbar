package main

import (
	"crypto/md5"
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
)

func getPrivateKey() (*rsa.PrivateKey, string) {
	keyBytes, err := fs.ReadFile("jwtRS256.key")
	if err != nil {
		log.Fatalf("Failed to read private key file: %s", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatalf("Failed to parse private keyfile: %s", err)
	}
	return key, getKidFromBytes(keyBytes)
}

func getPublicKey() (*rsa.PublicKey, string) {
	keyBytes, err := fs.ReadFile("jwtRS256.key.pub")
	if err != nil {
		log.Fatalf("Failed to read public key file: %s", err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatalf("Failed to parse public keyfile: %s", err)
	}
	return key, getKidFromBytes(keyBytes)
}

func getKidFromBytes(key []byte) string {
	signKeyBytePrint := md5.Sum(key)
	signKeyStringPrint := fmt.Sprintf("%x", signKeyBytePrint)
	return signKeyStringPrint
}
