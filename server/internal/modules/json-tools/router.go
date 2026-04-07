package jsontools

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/json-tools/handlers"
)

// RegisterRoutes đăng ký các endpoint của json-tools vào api router group
func RegisterRoutes(api *gin.RouterGroup) {
	jsonGroup := api.Group("/json")
	{
		jsonGroup.POST("/to-go", handlers.HandleJSONToGoStruct)
		jsonGroup.POST("/to-yaml", handlers.HandleJSONToYAML)
		jsonGroup.POST("/diff", handlers.HandleJSONDiff)
	}
}
