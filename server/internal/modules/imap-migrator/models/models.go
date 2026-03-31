package models

import "time"

// ─── Endpoint ─────────────────────────────────────────────────────────────────

type MigrationEndpoint struct {
	Host     string `json:"host"     binding:"required"`
	Port     int    `json:"port"     binding:"required,min=1,max=65535"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Security string `json:"security"` // "SSL" | "STARTTLS" | "NONE"
}

// ─── Requests ─────────────────────────────────────────────────────────────────

type TestConnectionRequest struct {
	Endpoint MigrationEndpoint `json:"endpoint" binding:"required"`
}

type ListFoldersRequest struct {
	Endpoint MigrationEndpoint `json:"endpoint" binding:"required"`
}

type StartRequest struct {
	Source  MigrationEndpoint `json:"source"  binding:"required"`
	Dest    MigrationEndpoint `json:"dest"    binding:"required"`
	Mode    string            `json:"mode"    binding:"required,oneof=all selected"`    // "all" | "selected"
	Folders []string          `json:"folders"` // chỉ dùng khi mode = "selected"
}

// ─── Folder Tree ──────────────────────────────────────────────────────────────

type FolderNode struct {
	Name      string        `json:"name"`
	FullPath  string        `json:"fullPath"`
	Delimiter string        `json:"delimiter"`
	Children  []*FolderNode `json:"children,omitempty"`
}

type ListFoldersResponse struct {
	Folders []*FolderNode `json:"folders"`
}

// ─── SSE Events ───────────────────────────────────────────────────────────────

type SSEEvent struct {
	Type         string `json:"type"`
	Folder       string `json:"folder,omitempty"`
	Total        int    `json:"total,omitempty"`
	Copied       int    `json:"copied,omitempty"`
	Skipped      int    `json:"skipped,omitempty"`
	Errors       int    `json:"errors,omitempty"`
	TotalFolders int    `json:"totalFolders,omitempty"`
	TotalCopied  int    `json:"totalCopied,omitempty"`
	TotalSkipped int    `json:"totalSkipped,omitempty"`
	TotalErrors  int    `json:"totalErrors,omitempty"`
	UID          uint32 `json:"uid,omitempty"`
	Size         int64  `json:"size,omitempty"`
	Message      string `json:"message,omitempty"`
}

// SSE Types:
// FOLDER_START, PROGRESS, FOLDER_DONE
// EMAIL_SKIPPED, EMAIL_ERROR, FOLDER_ERROR
// COMPLETE, ERROR, HEARTBEAT

// ─── Job Snapshot ─────────────────────────────────────────────────────────────

type JobSnapshot struct {
	JobID           string    `json:"jobId"`
	Status          string    `json:"status"` // running | done | error | cancelled
	Mode            string    `json:"mode"`
	SelectedFolders []string  `json:"selectedFolders"`
	TotalFolders    int       `json:"totalFolders"`
	CurrentFolder   string    `json:"currentFolder"`
	CompletedFolders int      `json:"completedFolders"`
	TotalCopied     int       `json:"totalCopied"`
	TotalSkipped    int       `json:"totalSkipped"`
	TotalErrors     int       `json:"totalErrors"`
	RecentErrors    []string  `json:"recentErrors"`
	LastError       string    `json:"lastError,omitempty"`
	StartedAt       time.Time `json:"startedAt"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
	CanReconnect    bool      `json:"canReconnect"`
}
