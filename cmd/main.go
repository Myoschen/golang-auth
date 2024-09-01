package main

import (
	"golang-auth/database"
	"golang-auth/handlers"
	"golang-auth/middlewares"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

func main() {
	r := gin.Default()

	db := database.NewDatabase()
	defer db.Close()
	rdb := database.NewRedis()
	defer rdb.Close()

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowMethods = []string{"GET", "POST", "DELETE", "OPTIONS", "PUT"}
	corsConfig.AllowHeaders = []string{"Authorization", "Content-Type", "Upgrade", "Origin", "Connection", "Accept-Encoding", "Accept-Language", "Host", "Access-Control-Request-Method", "Access-Control-Request-Headers"}
	r.Use(cors.New(corsConfig))

	authRoutes := r.Group("/auth")
	authRoutes.POST("/login", handlers.Login(db))
	authRoutes.POST("/register", handlers.Register(db))
	authRoutes.POST("/logout", middlewares.AuthMiddleware(rdb), handlers.Logout(rdb))
	authRoutes.POST("/refresh", middlewares.AuthMiddleware(rdb), handlers.Refresh(rdb))

	r.Run(":4000")

}
