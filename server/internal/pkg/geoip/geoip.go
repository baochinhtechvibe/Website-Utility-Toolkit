package geoip

import (
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/oschwald/geoip2-golang"
)

var (
	GeoIPDB  *geoip2.Reader
	GeoASNDB *geoip2.Reader
)

func init() {
	GeoIPDB = openGeoIPDB("GeoLite2-City.mmdb")
	if GeoIPDB == nil {
		log.Println("Không tìm thấy GeoLite2-City.mmdb, thông tin vị trí IP sẽ không khả dụng")
	} else {
		log.Println("Đã load thành công GeoLite2-City.mmdb")
	}

	GeoASNDB = openGeoIPDB("GeoLite2-ASN.mmdb")
	if GeoASNDB == nil {
		log.Println("Không tìm thấy GeoLite2-ASN.mmdb, thông tin ASN sẽ không khả dụng")
	} else {
		log.Println("Đã load thành công GeoLite2-ASN.mmdb")
	}
}

func openGeoIPDB(filename string) *geoip2.Reader {
	for _, path := range geoIPCandidatePaths(filename) {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		reader, err := geoip2.Open(path)
		if err == nil {
			return reader
		}
		log.Printf("Không thể mở GeoIP DB %s: %v", path, err)
	}
	return nil
}

func geoIPCandidatePaths(filename string) []string {
	paths := []string{
		filepath.Join("geoip", filename),
		filepath.Join("server", "geoip", filename),
	}

	if _, currentFile, _, ok := runtime.Caller(0); ok {
		// Traverse up from pkg/geoip/geoip.go to server/
		// pkg -> internal -> server -> root
		serverDir := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
		paths = append(paths, filepath.Join(serverDir, "geoip", filename))
	}

	return paths
}
