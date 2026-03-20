// ============================================
// FILE: internal/modules/ssl/routes.go
//
// Đăng ký các endpoint SSL vào Gin router group.
// File này dùng CHUNG cho tất cả tool trong ssl/:
//   - SSL Checker
//   - CSR Decoder (sẽ thêm sau)
//   - Cer Decoder (sẽ thêm sau)
//   - Key Matcher (sẽ thêm sau)
// ============================================

package ssl

import (
	"github.com/gin-gonic/gin"
	checkerHandlers "tools.bctechvibe.com/server/internal/modules/ssl/ssl-checker/handlers"
)

// RegisterRoutes gắn các endpoint SSL vào router group /api
func RegisterRoutes(api *gin.RouterGroup) {
	sslGroup := api.Group("/ssl")
	{
		// SSL Checker
		sslGroup.POST("/check", checkerHandlers.HandleSSLCheck)

		// CSR Decoder (sẽ thêm sau)
		// sslGroup.POST("/csr/decode", csrHandlers.HandleCSRDecode)

		// Cer Decoder (sẽ thêm sau)
		// sslGroup.POST("/cer/decode", cerHandlers.HandleCerDecode)
	}
}
