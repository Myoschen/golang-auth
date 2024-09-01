package middlewares

import (
	"context"
	"golang-auth/utils"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func AuthMiddleware(rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Missing authorization header"})
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenParts := strings.Split(tokenString, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization header format"})
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenString = tokenParts[1]
		claims, err := utils.VerifyToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid or expired token"})
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Expired token"})
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if _, err := rdb.Get(context.Background(), "bl_"+tokenString).Result(); err == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("userID", claims["user_id"])
		c.Set("token", tokenString)
		c.Set("tokenExp", claims["exp"])
		c.Next()
	}
}
