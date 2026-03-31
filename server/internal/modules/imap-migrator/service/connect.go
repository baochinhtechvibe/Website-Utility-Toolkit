package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

const dialTimeout = 10 * time.Second

// ─── Safe Dialer ─────────────────────────────────────────────────────────────
// Resolve host -> validate safe IP -> dial IP (SSRF protection)

func safeDial(ctx context.Context, host string, port int) (net.Conn, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("không phân giải được hostname")
	}

	var safeIP net.IP
	for _, ip := range ips {
		if validator.IsSafeIP(ip) {
			safeIP = ip
			break
		}
	}
	if safeIP == nil {
		return nil, fmt.Errorf("địa chỉ IP nội bộ không được phép")
	}

	addr := fmt.Sprintf("%s:%d", safeIP.String(), port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// ─── ValidateEndpoint ─────────────────────────────────────────────────────────

func ValidateEndpoint(ep models.MigrationEndpoint) error {
	ep.Host = strings.TrimSpace(ep.Host)
	if ep.Host == "" {
		return fmt.Errorf("host không được để trống")
	}

	sec := strings.ToUpper(ep.Security)
	if sec != "SSL" && sec != "STARTTLS" && sec != "NONE" {
		return fmt.Errorf("security phải là SSL, STARTTLS hoặc NONE")
	}
	return nil
}

// ─── Connect ─────────────────────────────────────────────────────────────────

func Connect(ctx context.Context, ep models.MigrationEndpoint) (*client.Client, error) {
	if err := ValidateEndpoint(ep); err != nil {
		return nil, err
	}

	host := strings.TrimSpace(ep.Host)
	sec := strings.ToUpper(ep.Security)

	switch sec {
	case "SSL":
		// Dial safe IP trực tiếp, TLS ServerName vẫn dùng hostname gốc
		conn, err := safeDial(ctx, host, ep.Port)
		if err != nil {
			return nil, FriendlyError(err)
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, FriendlyError(err)
		}
		c, err := client.New(tlsConn)
		if err != nil {
			return nil, FriendlyError(err)
		}
		if err := c.Login(ep.Username, ep.Password); err != nil {
			c.Logout()
			return nil, FriendlyError(err)
		}
		return c, nil

	case "STARTTLS":
		conn, err := safeDial(ctx, host, ep.Port)
		if err != nil {
			return nil, FriendlyError(err)
		}
		c, err := client.New(conn)
		if err != nil {
			conn.Close()
			return nil, FriendlyError(err)
		}
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			c.Logout()
			return nil, FriendlyError(err)
		}
		if err := c.Login(ep.Username, ep.Password); err != nil {
			c.Logout()
			return nil, FriendlyError(err)
		}
		return c, nil

	default: // NONE
		log.Warn().Str("host", host).Int("port", ep.Port).Msg("CẢNH BÁO: Kết nối tới máy chủ IMAP không được mã hóa (Security=NONE). Thông tin đăng nhập có thể bị lộ qua mạng.")
		conn, err := safeDial(ctx, host, ep.Port)
		if err != nil {
			return nil, FriendlyError(err)
		}
		c, err := client.New(conn)
		if err != nil {
			conn.Close()
			return nil, FriendlyError(err)
		}
		if err := c.Login(ep.Username, ep.Password); err != nil {
			c.Logout()
			return nil, FriendlyError(err)
		}
		return c, nil
	}
}

// ─── TestConnection ──────────────────────────────────────────────────────────

func TestConnection(ctx context.Context, ep models.MigrationEndpoint) error {
	c, err := Connect(ctx, ep)
	if err != nil {
		return err
	}
	defer c.Logout()
	return nil
}
