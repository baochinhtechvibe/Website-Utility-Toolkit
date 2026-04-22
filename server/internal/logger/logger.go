package logger

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger khởi tạo logger cho toàn bộ ứng dụng.
//   - level: mức log (debug, info, warn, error)
//   - env: môi trường (development → ConsoleWriter màu, production → JSON thuần)
func InitLogger(level string, env string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	ll := zerolog.InfoLevel
	switch strings.ToLower(level) {
	case "debug":
		ll = zerolog.DebugLevel
	case "warn":
		ll = zerolog.WarnLevel
	case "error":
		ll = zerolog.ErrorLevel
	}
	zerolog.SetGlobalLevel(ll)

	// Production: JSON thuần (hiệu suất cao, dễ tích hợp log aggregator)
	// Development: ConsoleWriter có màu sắc, dễ đọc khi debug
	if strings.ToLower(env) == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	} else {
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
}
