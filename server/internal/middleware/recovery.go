package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/response"
)

func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Error().Interface("panic", err).Msg("Recovered from panic")
				response.Error(c, http.StatusInternalServerError, "Internal Server Error")
				c.Abort()
			}
		}()
		c.Next()
	}
}
