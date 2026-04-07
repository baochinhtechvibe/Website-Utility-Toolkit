package models

import "time"

type WebLatencyRequest struct {
	URL         string `json:"url" binding:"required"`
	DeepTest    bool   `json:"deepTest"`
	BypassCache bool   `json:"bypassCache"`
}

type TimingMetrics struct {
	DNSLookup    time.Duration `json:"dnsLookup"`
	TCPConnect   time.Duration `json:"tcpConnect"`
	TLSHandshake time.Duration `json:"tlsHandshake"`
	TTFB         time.Duration `json:"ttfb"`
	ContentDownload time.Duration `json:"contentDownload"`
	Total        time.Duration `json:"total"`
}

type CompressionInfo struct {
	Encoding     string `json:"encoding"`
	IsCompressed bool   `json:"isCompressed"`
	ContentType  string `json:"contentType"`
	CacheControl string `json:"cacheControl"`
	ETag         string `json:"etag"`
	XCache       string `json:"xCache"`
	Server       string `json:"server"`
	HTTPVersion  string `json:"httpVersion"`
}

type Hop struct {
	URL        string        `json:"url"`
	StatusCode int           `json:"statusCode"`
	Metrics    TimingMetrics `json:"metrics"`
}

type WebLatencyResult struct {
	TargetURL       string          `json:"targetUrl"`
	FinalURL        string          `json:"finalUrl"`
	IsUp            bool            `json:"isUp"`
	RedirectHops    []Hop           `json:"redirectHops"`
	PrimaryMetrics  TimingMetrics   `json:"primaryMetrics"` // Metrics of the final round
	Compression     CompressionInfo `json:"compression"`
	DeepTestResults *DeepTestInfo   `json:"deepTestResults,omitempty"`
}

type DeepTestInfo struct {
	MinTTFB    time.Duration `json:"minTtfb"`
	MedianTTFB time.Duration `json:"medianTtfb"`
	MaxTTFB    time.Duration `json:"maxTtfb"`
	Rounds     int           `json:"rounds"`
}
