package logger

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func InitLogger(level string) {
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

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
}
