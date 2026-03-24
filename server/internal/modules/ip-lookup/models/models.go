package models


type IPInfo struct {
	IP          string    `json:"ip"`
	Version     string    `json:"version"` // IPv4 or IPv6
	Decimal     string    `json:"decimal"`
	Hostname    string    `json:"hostname"`
	ASN         string    `json:"asn"`
	ISP         string    `json:"isp"`
	Services    string    `json:"services"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	Region      string    `json:"region"`
	City        string    `json:"city"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	TimeZone    string    `json:"timezone"`
	Browser     string    `json:"browser"`
	OS          string    `json:"os"`
	UserAgent   string    `json:"user_agent"`
}

