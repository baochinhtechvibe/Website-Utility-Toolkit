package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailJobLog(t *testing.T) {
	// Set up dummy GetDataDir for testing
	tmpDir := t.TempDir()
	os.Setenv("IMAP_DATA_DIR", tmpDir)

	logsDir := filepath.Join(tmpDir, "logs")
	os.MkdirAll(logsDir, 0755)

	jobID := "test_tail_log"
	logFile := filepath.Join(logsDir, "job_"+jobID+".log")

	// Case 1: File không tồn tại
	lines, offset := TailJobLog(jobID, 10, 0)
	if len(lines) != 0 || offset != 0 {
		t.Errorf("Expected nil, 0 but got %v, %d", lines, offset)
	}

	// Tạo file log nhỏ
	content := "Line 1\nLine 2\nLine 3\n"
	os.WriteFile(logFile, []byte(content), 0644)

	// Case 2: File nhỏ, fromOffset = 0
	lines, offset = TailJobLog(jobID, 10, 0)
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}
	if offset != int64(len(content)) {
		t.Errorf("Expected offset %d, got %d", len(content), offset)
	}

	// Case 3: File nhỏ, fromOffset = 0, numLines nhỏ hơn số dòng
	lines, offset = TailJobLog(jobID, 2, 0)
	if len(lines) != 2 || lines[0] != "Line 2" || lines[1] != "Line 3" {
		t.Errorf("Expected last 2 lines, got %v", lines)
	}

	// Case 4: fromOffset = <giữa file>
	lines, offset = TailJobLog(jobID, 10, 7) // Bỏ qua "Line 1\n"
	if len(lines) != 2 || lines[0] != "Line 2" || lines[1] != "Line 3" {
		t.Errorf("Expected Line 2 and Line 3, got %v", lines)
	}
	if offset != int64(len(content)) {
		t.Errorf("Expected new offset %d, got %d", len(content), offset)
	}

	// Case 5: fromOffset >= fileSize
	lines, offset = TailJobLog(jobID, 10, int64(len(content)))
	if len(lines) != 0 || offset != int64(len(content)) {
		t.Errorf("Expected nil, fileSize but got %v, %d", lines, offset)
	}

	// Case 6: File lớn (>64KB) và fromOffset = 0
	var sb strings.Builder
	for i := 1; i <= 20000; i++ {
		sb.WriteString(fmt.Sprintf("Line %05d\n", i))
	}
	largeContent := sb.String()
	os.WriteFile(logFile, []byte(largeContent), 0644)

	lines, offset = TailJobLog(jobID, 500, 0)
	if len(lines) != 500 {
		t.Errorf("Expected 500 lines, got %d", len(lines))
	}
	if offset != int64(len(largeContent)) {
		t.Errorf("Expected offset %d, got %d", len(largeContent), offset)
	}

	// Case 7: File lớn (>64KB), fromOffset = 0 -> test read limit progress
	// test read size < chunk -> should not exceed maxRead (64KB)
	lines, offset = TailJobLog(jobID, 500, 10)
	if offset > 10+64*1024 {
		t.Errorf("Expected maxRead 64KB chunk, got offset %d", offset)
	}

	// Case 8: Loop to reconstruct entire file from fromOffset > 0
	// Bắt đầu từ offset tương ứng bỏ qua dòng đầu tiên (độ dài của "Line 00001\n" là 11 bytes)
	var currentOffset int64 = 11
	var allLines []string
	for {
		chunkLines, newOffset := TailJobLog(jobID, 100000, currentOffset)
		if len(chunkLines) > 0 {
			allLines = append(allLines, chunkLines...)
		}
		if newOffset <= currentOffset {
			break
		}
		currentOffset = newOffset
	}

	if len(allLines) != 19999 {
		t.Errorf("Expected 19999 lines after loop reconstruct, got %d", len(allLines))
	} else {
		if allLines[0] != "Line 00002" {
			t.Errorf("Expected first line 'Line 00002', got %q", allLines[0])
		}
		if allLines[len(allLines)-1] != "Line 20000" {
			t.Errorf("Expected last line 'Line 20000', got %q", allLines[len(allLines)-1])
		}
	}
}
