package iplookup

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ip-lookup/handlers"
)

func RegisterRoutes(api *gin.RouterGroup) {
	ipGroup := api.Group("/ip-lookup")
	{
		ipGroup.GET("/my-ip", handlers.HandleMyIP)
	}
}
