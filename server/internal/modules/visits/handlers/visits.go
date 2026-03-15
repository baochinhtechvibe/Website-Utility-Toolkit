package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type VisitStats struct {
	TotalVisits   int64               `json:"total_visits"`
	TodayVisits   int64               `json:"today_visits"`
	LastResetDate string              `json:"last_reset_date"`
	DailyIPs      map[string]struct{} `json:"daily_ips"` // Used internally, saved as map for O(1)
	DailyIPVals   []string            `json:"daily_ip_vals"` // Used for JSON marshal
}

var (
	statsFile = "data/visits.json"
	statsMu   sync.Mutex
	currentStats *VisitStats
)

// Ensure stats file exists
func initStats() error {
	statsMu.Lock()
	defer statsMu.Unlock()

	dir := filepath.Dir(statsFile)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}

	if _, err := os.Stat(statsFile); os.IsNotExist(err) {
		currentStats = &VisitStats{
			TotalVisits:   0,
			TodayVisits:   0,
			LastResetDate: time.Now().Format("2006-01-02"),
			DailyIPs:      make(map[string]struct{}),
			DailyIPVals:   []string{},
		}
		return saveStatsLocked()
	}

	data, err := os.ReadFile(statsFile)
	if err != nil {
		return err
	}

	currentStats = &VisitStats{DailyIPs: make(map[string]struct{})}
	if err := json.Unmarshal(data, currentStats); err != nil {
		// If corruption, reset
		currentStats = &VisitStats{
			TotalVisits:   0,
			TodayVisits:   0,
			LastResetDate: time.Now().Format("2006-01-02"),
			DailyIPs:      make(map[string]struct{}),
			DailyIPVals:   []string{},
		}
	}

	// Rebuild map from slice
	for _, ip := range currentStats.DailyIPVals {
		currentStats.DailyIPs[ip] = struct{}{}
	}

	return nil
}

func saveStatsLocked() error {
	// Rebuild slice from map before saving
	currentStats.DailyIPVals = []string{}
	for ip := range currentStats.DailyIPs {
		currentStats.DailyIPVals = append(currentStats.DailyIPVals, ip)
	}

	data, err := json.MarshalIndent(currentStats, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statsFile, data, 0644)
}

func GetStats(c *gin.Context) {
	if currentStats == nil {
		initStats()
	}
	
	statsMu.Lock()
	defer statsMu.Unlock()

	today := time.Now().Format("2006-01-02")
	if currentStats.LastResetDate != today {
		currentStats.TodayVisits = 0
		currentStats.LastResetDate = today
		currentStats.DailyIPs = make(map[string]struct{})
		saveStatsLocked()
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"total_visits": currentStats.TotalVisits,
		"today_visits": currentStats.TodayVisits,
	})
}

func TrackVisit(c *gin.Context) {
	if currentStats == nil {
		initStats()
	}

	statsMu.Lock()
	defer statsMu.Unlock()

	today := time.Now().Format("2006-01-02")
	
	// Reset logic at midnight
	if currentStats.LastResetDate != today {
		currentStats.TodayVisits = 0
		currentStats.LastResetDate = today
		currentStats.DailyIPs = make(map[string]struct{})
	}

	ip := c.ClientIP()

	// Only increment if IP hasn't visited today
	if _, exists := currentStats.DailyIPs[ip]; !exists {
		currentStats.DailyIPs[ip] = struct{}{}
		currentStats.TotalVisits++
		currentStats.TodayVisits++
		saveStatsLocked()
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"total_visits": currentStats.TotalVisits,
		"today_visits": currentStats.TodayVisits,
	})
}
