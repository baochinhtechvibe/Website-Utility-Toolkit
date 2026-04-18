package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"tools.bctechvibe.com/server/internal/platform/validator"
)

var (
	defaultClient  *http.Client
	insecureClient *http.Client
	once           sync.Once
)

func initClients() {
	defaultClient = createClient(false)
	insecureClient = createClient(true)
}

func createClient(ignoreTLS bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second, // Tăng keepalive
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			if ip := net.ParseIP(host); ip != nil {
				if !validator.IsSafeIP(ip) {
					return nil, errors.New("SSRF Blocked: private IP")
				}
				return dialer.DialContext(ctx, network, addr)
			}

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			var safeIP net.IP
			for _, ip := range ips {
				if validator.IsSafeIP(ip) {
					safeIP = ip
					break
				}
			}

			if safeIP == nil {
				return nil, errors.New("SSRF Blocked: private network")
			}

			return dialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, // Tăng thêm chút cho link chậm
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: ignoreTLS,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second, // Timeout tổng quát
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SafeHTTPClient trả về singleton client dựa trên cấu hình TLS
func SafeHTTPClient(ignoreTLS bool, timeout time.Duration) *http.Client {
	once.Do(initClients)
	if ignoreTLS {
		return insecureClient
	}
	return defaultClient
}

// SafeBasePageClient trả về client riêng để fetch trang gốc (có follow redirect)
func SafeBasePageClient(ignoreTLS bool) *http.Client {
	// Trang gốc cần follow redirect tự động
	baseClient := createClient(ignoreTLS)
	baseClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("quá nhiều chuyển hướng (5+)")
		}
		return nil
	}
	return baseClient
}
