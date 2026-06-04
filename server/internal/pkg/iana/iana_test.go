package iana

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchAndCacheGTLDList(t *testing.T) {
	var mockHTML = "<!DOCTYPE html>\n<html>\n<body>\n<table id=\"tld-table\" class=\"iana-table\">\n<tbody>\n"
	// Thêm các test case chính
	mockHTML += "<tr><td><span class=\"domain tld\"><a href=\"/domains/root/db/com.html\">.com</a></span></td><td>generic</td></tr>\n"
	mockHTML += "<tr><td><span class=\"domain tld\"><a href=\"/domains/root/db/io.html\">.io</a></span></td><td>country-code</td></tr>\n"
	mockHTML += "<tr><td><span class=\"domain tld\"><a href=\"/domains/root/db/app.html\">.app</a></span></td><td>generic</td></tr>\n"
	mockHTML += "<tr><td><span class=\"domain tld\"><a href=\"/domains/root/db/uk.html\">.uk</a></span></td><td>country-code</td></tr>\n"
	
	// Thêm padding cho đủ > 50 entries
	for i := 0; i < 60; i++ {
		mockHTML += "<tr><td><span class=\"domain tld\"><a href=\"/domains/root/db/dummy" + string(rune('a'+(i%26))) + string(rune('a'+(i/26))) + ".html\">.dummy" + string(rune('a'+(i%26))) + string(rune('a'+(i/26))) + "</a></span></td><td>generic</td></tr>\n"
	}
	mockHTML += "</tbody>\n</table>\n</body>\n</html>"
	
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(mockHTML))
	}))
	defer ts.Close()

	// Override ianaURL
	origIanaURL := ianaRootZoneURL
	defer func() { ianaRootZoneURL = origIanaURL }()
	ianaRootZoneURL = ts.URL

	// Clear cache
	emptyMap := make(map[string]bool)
	gtldSet.Store(&emptyMap)

	err := FetchAndCacheGTLDList()
	assert.NoError(t, err)

	// Validate results
	assert.True(t, IsGTLD("com"))
	assert.True(t, IsGTLD("app"))
	assert.False(t, IsGTLD("io"))
	assert.False(t, IsGTLD("uk"))
	assert.False(t, IsGTLD("xyz")) // Not in mock
}
