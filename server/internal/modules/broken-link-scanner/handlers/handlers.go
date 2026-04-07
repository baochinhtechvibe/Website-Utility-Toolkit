package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/response"
)

var blsCache = cache.NewMemoryCache(30 * time.Minute)

// HandleScan kicks off sync POST link checking mechanism.
func HandleScan(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu nhập vào chưa đúng định dạng. Vui lòng kiểm tra lại URL hoặc cấu hình.")
		return
	}

	// Hard timeout execution limit in order not to freeze connection up to a minute.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 35*time.Second)
	defer cancel()

	cacheKey := "bls:" + req.URL + ":" + req.Scope
	if !req.BypassCache {
		if data, fetchedAt, found := blsCache.Get(cacheKey); found {
			response.Success(c, data, true, fetchedAt)
			return
		}
	} else {
		blsCache.Delete(cacheKey)
	}

	// Run scanner service inside a background routine to track context dropout
	dataChan := make(chan models.ScanData, 1)
	errChan := make(chan error, 1)

	go func() {
		data, err := service.ProcessScan(req) // We don't propagate explicit ctx across worker loop to keep pure structure, but we cap it outwardly.
		if err != nil {
			errChan <- err
			return
		}
		dataChan <- data
	}()

	select {
	case <-ctx.Done():
		response.Error(c, http.StatusGatewayTimeout, "Pha thực thi vượt quá giới hạn 35 giây do quá nhiều Links hoặc Server tải quá chậm.")
		return
	case err := <-errChan:
		response.Error(c, http.StatusInternalServerError, err.Error())
		return
	case scanData := <-dataChan:
		blsCache.Set(cacheKey, scanData)
		response.Success(c, scanData, false, time.Now())
		return
	}
}
