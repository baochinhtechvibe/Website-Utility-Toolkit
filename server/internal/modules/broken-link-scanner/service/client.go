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

// SafeHTTPClient creates an HTTP client with tight timeouts and SSRF protection.
func SafeHTTPClient(ignoreTLS bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Prevent parsing errors if it's already an IP
			if ip := net.ParseIP(host); ip != nil {
				if !validator.IsSafeIP(ip) {
					return nil, errors.New("SSRF Blocked: Tries to connect to a private IP")
				}
				return dialer.DialContext(ctx, network, addr)
			}

			// Lookup domains
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
				return nil, errors.New("SSRF Blocked: Domain resolves to private networks")
			}

			// Dial the strict safe IP
			safeAddr := net.JoinHostPort(safeIP.String(), port)
			return dialer.DialContext(ctx, network, safeAddr)
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: ignoreTLS,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Do not auto-follow redirects, we will handle it manually for meticulous tracing
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Redirect Following Logic Client (Only for extracting the Base page)
func SafeBasePageClient(ignoreTLS bool) *http.Client {
	client := SafeHTTPClient(ignoreTLS, 15*time.Second)
	// Base page needs to automatically parse follow
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("stopped after 5 redirects")
		}
		return nil
	}
	return client
}
