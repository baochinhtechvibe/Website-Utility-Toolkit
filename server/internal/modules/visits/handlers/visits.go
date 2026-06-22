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
	DailyIPs      map[string]struct{} `json:"daily_ips"`     // Used internally, saved as map for O(1)
	DailyIPVals   []string            `json:"daily_ip_vals"` // Used for JSON marshal
}

var (
	statsFile = "data/visits.json"
	statsMu   sync.Mutex
	// Store stats per tool ID (e.g. "home", "imap-migrator")
	globalStats map[string]*VisitStats
)

// Ensure stats file exists and load it
func initStats() error {
	statsMu.Lock()
	defer statsMu.Unlock()

	dir := filepath.Dir(statsFile)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}

	globalStats = make(map[string]*VisitStats)

	if _, err := os.Stat(statsFile); os.IsNotExist(err) {
		// No file, start fresh
		return saveStatsLocked()
	}

	data, err := os.ReadFile(statsFile)
	if err != nil {
		return err
	}

	// Try to unmarshal into the new map format
	err = json.Unmarshal(data, &globalStats)
	if err != nil || len(globalStats) == 0 {
		// It might be the old format (single root object)
		var oldFormat VisitStats
		if errOld := json.Unmarshal(data, &oldFormat); errOld == nil {
			if oldFormat.DailyIPs == nil {
				oldFormat.DailyIPs = make(map[string]struct{})
			}
			globalStats = map[string]*VisitStats{
				"home": &oldFormat,
			}
		} else {
			// Complete corruption, start fresh
			globalStats = make(map[string]*VisitStats)
		}
	}

	// Rebuild mapped sets from slices for all tools
	for _, stats := range globalStats {
		if stats.DailyIPs == nil {
			stats.DailyIPs = make(map[string]struct{})
		}
		for _, ip := range stats.DailyIPVals {
			stats.DailyIPs[ip] = struct{}{}
		}
	}

	return nil
}

func getOrCreateToolStats(toolName string) *VisitStats {
	stats, exists := globalStats[toolName]
	if !exists {
		stats = &VisitStats{
			TotalVisits:   0,
			TodayVisits:   0,
			LastResetDate: time.Now().Format("2006-01-02"),
			DailyIPs:      make(map[string]struct{}),
			DailyIPVals:   []string{},
		}
		globalStats[toolName] = stats
	}
	return stats
}

func saveStatsLocked() error {
	// Rebuild slices from maps before saving
	for _, stats := range globalStats {
		stats.DailyIPVals = []string{}
		for ip := range stats.DailyIPs {
			stats.DailyIPVals = append(stats.DailyIPVals, ip)
		}
	}

	data, err := json.MarshalIndent(globalStats, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statsFile, data, 0644)
}

func GetStats(c *gin.Context) {
	if globalStats == nil {
		initStats()
	}

	toolName := c.DefaultQuery("tool", "home")

	statsMu.Lock()
	defer statsMu.Unlock()

	stats := getOrCreateToolStats(toolName)

	today := time.Now().Format("2006-01-02")
	if stats.LastResetDate != today {
		stats.TodayVisits = 0
		stats.LastResetDate = today
		stats.DailyIPs = make(map[string]struct{})
		saveStatsLocked()
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"tool":         toolName,
		"total_visits": stats.TotalVisits,
		"today_visits": stats.TodayVisits,
	})
}

func TrackVisit(c *gin.Context) {
	if globalStats == nil {
		initStats()
	}

	toolName := c.DefaultQuery("tool", "home")

	statsMu.Lock()
	defer statsMu.Unlock()

	stats := getOrCreateToolStats(toolName)
	today := time.Now().Format("2006-01-02")

	// Reset logic at midnight
	if stats.LastResetDate != today {
		stats.TodayVisits = 0
		stats.LastResetDate = today
		stats.DailyIPs = make(map[string]struct{})
	}

	ip := c.ClientIP()

	// Only increment if IP hasn't visited today for this specific tool
	if _, exists := stats.DailyIPs[ip]; !exists {
		stats.DailyIPs[ip] = struct{}{}
		stats.TotalVisits++
		stats.TodayVisits++
		saveStatsLocked()
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"tool":         toolName,
		"total_visits": stats.TotalVisits,
		"today_visits": stats.TodayVisits,
	})
}
