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
	csrHandlers "tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/handlers"
	csrService "tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/service"

	cerHandlers "tools.bctechvibe.com/server/internal/modules/ssl/cer-decoder/handlers"
	cerService "tools.bctechvibe.com/server/internal/modules/ssl/cer-decoder/service"

	matcherHandlers "tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/handlers"
	matcherService "tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/service"

	converterHandlers "tools.bctechvibe.com/server/internal/modules/ssl/converter/handlers"
	converterService "tools.bctechvibe.com/server/internal/modules/ssl/converter/service"

	generatorHandlers "tools.bctechvibe.com/server/internal/modules/ssl/generator/handlers"
	generatorService "tools.bctechvibe.com/server/internal/modules/ssl/generator/service"
)

// RegisterRoutes gắn các endpoint SSL vào router group /api
func RegisterRoutes(api *gin.RouterGroup) {

	// Init Services
	csrSvc := csrService.New()
	csrHdl := csrHandlers.NewCSRHandler(csrSvc)

	sslGroup := api.Group("/ssl")
	{
		// SSL Checker
		sslGroup.POST("/check", checkerHandlers.HandleSSLCheck)

		// CSR Decoder
		sslGroup.POST("/csr/decode", csrHdl.HandleCSRDecode)

		// Cer Decoder
		cerSvc := cerService.New()
		cerHdl := cerHandlers.NewCERHandler(cerSvc)
		sslGroup.POST("/cer/decode", cerHdl.HandleCerDecode)

		// Key Matcher
		matcherSvc := matcherService.New()
		matcherHdl := matcherHandlers.NewKeyMatchHandler(matcherSvc)
		sslGroup.POST("/key-matcher/match", matcherHdl.HandleKeyMatch)

		// SSL Converter
		converterSvc := converterService.New()
		converterHdl := converterHandlers.NewConvertHandler(converterSvc)
		sslGroup.POST("/converter/convert", converterHdl.HandleConvert)

		// CSR Generator
		generatorSvc := generatorService.NewGeneratorService()
		generatorHdl := generatorHandlers.NewGeneratorHandler(generatorSvc)
		sslGroup.POST("/generator/csr", generatorHdl.GenerateCSR)
	}
}
