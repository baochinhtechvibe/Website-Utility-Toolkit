package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"tools.bctechvibe.com/server/internal/platform/validator"
)

var (
	defaultClient      *http.Client
	insecureClient     *http.Client
	defaultBaseClient  *http.Client
	insecureBaseClient *http.Client
)

func init() {
	initClients()
}

func initClients() {
	defaultClient = createClient(false, false)
	insecureClient = createClient(true, false)
	defaultBaseClient = createClient(false, true)
	insecureBaseClient = createClient(true, true)
}

func createClient(ignoreTLS bool, followRedirect bool) *http.Client {
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
		ResponseHeaderTimeout: 7 * time.Second, // Giảm xuống 7s để loại bỏ sớm các link quá chậm
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          500, // Tăng lên để phục vụ nhiều worker hơn
		MaxIdleConnsPerHost:   50,  // Tăng lên để quét nhanh hơn trên cùng 1 domain
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: ignoreTLS,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // Giảm xuống 10s cho mỗi link đơn lẻ
	}

	if !followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("quá nhiều chuyển hướng (5+)")
			}
			return nil
		}
	}

	return client
}

// SafeHTTPClient trả về singleton client dựa trên cấu hình TLS
func SafeHTTPClient(ignoreTLS bool) *http.Client {
	if ignoreTLS {
		return insecureClient
	}
	return defaultClient
}

// SafeBasePageClient trả về client riêng để fetch trang gốc (có follow redirect)
func SafeBasePageClient(ignoreTLS bool) *http.Client {
	if ignoreTLS {
		return insecureBaseClient
	}
	return defaultBaseClient
}
