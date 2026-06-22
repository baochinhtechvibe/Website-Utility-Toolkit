package errutil

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslateErrorDNSRcodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "NXDOMAIN",
			err:  errors.New("NXDOMAIN"),
			want: "Tên miền không tồn tại",
		},
		{
			name: "SERVFAIL",
			err:  errors.New("SERVFAIL"),
			want: "SERVFAIL",
		},
		{
			name: "REFUSED",
			err:  errors.New("REFUSED"),
			want: "REFUSED",
		},
		{
			name: "FORMERR",
			err:  errors.New("FORMERR"),
			want: "FORMERR",
		},
		{
			name: "unknown DNS code",
			err:  errors.New("DNS error code 9"),
			want: "mã lỗi không thành công",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TranslateError(tt.err)
			if !strings.Contains(got, tt.want) {
				t.Fatalf("TranslateError(%q) = %q, want substring %q", tt.err.Error(), got, tt.want)
			}
			if strings.Contains(got, "không xác định") {
				t.Fatalf("TranslateError(%q) returned generic message: %q", tt.err.Error(), got)
			}
		})
	}
}

func TestTranslateErrorConnectionRefusedIsNotDNSRefused(t *testing.T) {
	got := TranslateError(errors.New("dial tcp 203.0.113.10:443: connect: connection refused"))
	if strings.Contains(got, "REFUSED") || strings.Contains(got, "truy vấn DNS") {
		t.Fatalf("TranslateError() = %q, want network connection refused message", got)
	}
	if !strings.Contains(got, "Kết nối bị từ chối") {
		t.Fatalf("TranslateError() = %q, want connection refused translation", got)
	}
}
