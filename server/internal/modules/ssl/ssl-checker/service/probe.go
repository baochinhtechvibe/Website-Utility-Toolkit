// ============================================
// FILE: ssl-checker/service/probe.go
//
// HTTP probe: gửi request tới server để lấy
// response headers phục vụ detect server type.
// ============================================

package service

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

// ===========================
// Probe types
// ===========================

type probeDef struct {
	client *http.Client
	url    string
	method string
}

// Probe chứa kết quả của một lần thăm dò HTTP
type Probe struct {
	URL      string
	Method   string
	Response *http.Response
	Error    error
}

// ===========================
// Collect probes
// ===========================

// collectProbes gửi HTTP request tới domain để lấy response headers.
// Chạy tuần tự, dừng ngay khi có response thành công (tránh bị WAF chặn).
func collectProbes(ctx context.Context, domain string, ip string) []*Probe {

	dialer := &net.Dialer{Timeout: HTTPProbeTimeout}

	// Ép TCP dial thẳng tới IP đã resolve, tránh DNS hang
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && host == domain {
			addr = net.JoinHostPort(ip, port)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.DialContext = dialContext
	baseTransport.ForceAttemptHTTP2 = false
	baseTransport.DisableKeepAlives = true

	strictTransport := baseTransport.Clone()

	insecureTransport := baseTransport.Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	plainTransport := baseTransport.Clone()

	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	strictClient := &http.Client{Timeout: HTTPProbeTimeout, Transport: strictTransport, CheckRedirect: noRedirect}
	insecureClient := &http.Client{Timeout: HTTPProbeTimeout, Transport: insecureTransport, CheckRedirect: noRedirect}
	plainClient := &http.Client{Timeout: HTTPProbeTimeout, Transport: plainTransport, CheckRedirect: noRedirect}

	defs := []probeDef{
		{strictClient, "https://" + domain, http.MethodGet},
		{insecureClient, "https://" + domain, http.MethodGet},
		{strictClient, "https://" + domain, http.MethodHead},
		{plainClient, "http://" + domain, http.MethodGet},
	}

	var validProbes []*Probe

	for _, d := range defs {
		resp, err := doRequest(ctx, d.client, d.url, d.method)

		p := &Probe{
			URL:      d.url,
			Method:   d.method,
			Response: resp,
			Error:    err,
		}
		validProbes = append(validProbes, p)

		if err == nil && resp != nil {
			break
		}
	}

	return validProbes
}

// ===========================
// HTTP request helper
// ===========================

func doRequest(
	ctx context.Context,
	client *http.Client,
	url string,
	method string,
) (*http.Response, error) {

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
			"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Chỉ cần headers → close body ngay
	resp.Body.Close()

	return resp, nil
}
