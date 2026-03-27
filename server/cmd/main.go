package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/config"
	"tools.bctechvibe.com/server/internal/logger"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/service"
	"tools.bctechvibe.com/server/internal/router"
)

func main() {
	cfg := config.LoadConfig()
	logger.InitLogger(cfg.LogLevel)

	// Dọn dẹp các file tạm của tiến trình IMAP Migrator nếu có từ trước
	service.StartupCleanup()

	r := router.SetupRouter()

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	// Khởi chạy server trên 1 goroutine
	go func() {
		log.Info().Str("port", cfg.Port).Msg("Server started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Failed to listen and serve")
		}
	}()

	// Đợi tín hiệu tắt (Graceful Shutdown)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("Shutting down server...")

	// Timeout 5 giây ráng lo xử lý cho xong request đang chạy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server exiting")
}
