package database

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func NewDatabase() *pgxpool.Pool {
	connString := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DATABASE_HOST"),
		os.Getenv("DATABASE_PORT"),
		os.Getenv("DATABASE_USER"),
		os.Getenv("DATABASE_PASSWORD"),
		os.Getenv("DATABASE_NAME"),
	)
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	return pool
}

func NewRedis() *redis.Client {
	addrString := fmt.Sprintf(
		"%s:%s",
		os.Getenv("REDIS_HOST"),
		os.Getenv("REDIS_PORT"),
	)
	db, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to convert `REDIS_DB` to `int` type: %v\n", err.Error())
		os.Exit(1)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addrString,
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       db,
	})
	return client
}
