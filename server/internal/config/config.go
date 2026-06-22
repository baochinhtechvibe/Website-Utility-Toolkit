package config

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

type Config struct {
	Port          string
	LogLevel      string
	AppEnv        string // "development" hoặc "production"
	DomScanAPIKey string
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

	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "production"
	}

	domscanKey := os.Getenv("DOMSCAN_API_KEY")

	return Config{
		Port:          port,
		LogLevel:      logLevel,
		AppEnv:        appEnv,
		DomScanAPIKey: domscanKey,
	}
}
