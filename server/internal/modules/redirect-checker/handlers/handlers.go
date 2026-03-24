package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/redirect-checker/models"
	"tools.bctechvibe.com/server/internal/modules/redirect-checker/service"
)

// HandleAnalyze processes the incoming request to analyze URL redirects.
func HandleAnalyze(c *gin.Context) {
	var req models.RedirectAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Invalid redirect analyze request payload")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request payload",
		})
		return
	}

	// Sanitize URL for logging to prevent log injection
	logURL := req.URL
	if len(logURL) > 256 {
		logURL = logURL[:253] + "..."
	}
	logURL = strings.ReplaceAll(logURL, "\n", "")
	logURL = strings.ReplaceAll(logURL, "\r", "")

	log.Info().Str("url", logURL).Msg("Starting redirect analysis")

	resp, err := service.AnalyzeRedirects(c.Request.Context(), req)
	if err != nil {
		log.Error().Err(err).Str("url", logURL).Msg("Failed to analyze redirects")
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to analyze redirects. Possible connection issue or blocked URL.",
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}
