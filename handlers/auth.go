package handlers

import (
	"context"
	"golang-auth/models"
	"golang-auth/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTokenExp  = time.Hour * 24
	refreshTokenExp = time.Hour * 24 * 7
)

func Login(db *pgxpool.Pool, rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input models.LoginInput

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		var user models.User
		row := db.QueryRow(context.Background(), "select * from users where email=$1", input.Email)
		if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt); err == pgx.ErrNoRows {
			c.JSON(http.StatusBadRequest, gin.H{"message": "User not found"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid credentials"})
			return
		}

		accessToken, err := utils.GenerateToken(user.ID, accessTokenExp)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}

		refreshToken, err := utils.GenerateToken(user.ID, refreshTokenExp)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}

		rdb.Set(context.Background(), user.ID, accessToken, accessTokenExp)
		rdb.Set(context.Background(), "refresh_"+user.ID, refreshToken, refreshTokenExp)

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

func Logout(rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		anyUserID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Not logged in yet"})
			return
		}

		userID, ok := anyUserID.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something wrong"})
			return
		}

		rdb.Del(context.Background(), userID, "refresh_"+userID)

		c.JSON(http.StatusOK, gin.H{"message": "Logout successfully"})
	}
}

func Register(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input models.RegisterInput

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		var userFound models.User
		row := db.QueryRow(context.Background(), "select * from users where email=$1", input.Email)
		if err := row.Scan(&userFound.ID, &userFound.Username, &userFound.Email, &userFound.Password, &userFound.CreatedAt, &userFound.UpdatedAt); err != pgx.ErrNoRows {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Email already used"})
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}

		// https://github.com/jackc/pgx/issues/411
		var user models.User
		row = db.QueryRow(context.Background(), "insert into users (username, email, password) values ($1, $2, $3) returning *", input.Username, input.Email, string(hash))
		if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "User registered successfully",
			"data":    user,
		})
	}
}

func Refresh(rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		anyUserID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Not logged in yet"})
			return
		}

		userID, ok := anyUserID.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Something wrong"})
			return
		}

		accessToken, err := utils.GenerateToken(userID, accessTokenExp)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}

		refreshToken, err := utils.GenerateToken(userID, refreshTokenExp)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}

		rdb.Set(context.Background(), userID, accessToken, accessTokenExp)
		rdb.Set(context.Background(), "refresh_"+userID, refreshToken, refreshTokenExp)

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}
