package main

import (
	"embed"
	"github.com/gin-gonic/gin"
	"log"
	"os"
)

//go:embed jwtRS256.key jwtRS256.key.pub
var fs embed.FS

func main() {
	r := NewEngine()
	registerRoutes(r)

	port := "8088"
	if envport := os.Getenv("PORT"); envport != "" {
		port = envport
	}
	log.Printf("Starting server on port :%s", port)

	err := r.Run(":" + port)
	if err != nil {
		log.Fatalf("Failed to run server: %s", err)
	}
}

func registerRoutes(r *gin.Engine) {
	r.GET("/.well-known/jwks.json", JwksHandler())
	r.POST("/oauth/token", TokenSignerHandler())
}
