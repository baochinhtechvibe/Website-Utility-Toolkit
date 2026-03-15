package config

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

type Config struct {
	Port     string
	LogLevel string
}

func LoadConfig() Config {
	err := godotenv.Load()
	if err != nil {
		log.Warn().Msg("No .env file found or failed to load, using system environment variables")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3101"
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	return Config{
		Port:     port,
		LogLevel: logLevel,
	}
}
