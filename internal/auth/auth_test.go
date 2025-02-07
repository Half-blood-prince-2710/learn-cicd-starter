package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		expect  string
		err     error
	}{
		{
			name:    "valid API key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expect:  "my-secret-key",
			err:     nil,
		},
		{
			name:    "valid API key with lowercase prefix",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expect:  "my-secret-key",
			err:     nil,
		},
		{
			name:    "missing authorization header",
			headers: http.Header{},
			expect:  "",
			err:     ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed authorization header (no ApiKey prefix)",
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expect:  "",
			err:     errors.New("malformed authorization header"),
		},
		{
			name:    "malformed authorization header (no key provided)",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			expect:  "",
			err:     errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expect {
				t.Errorf("expected key %q, got %q", tt.expect, key)
			}
			if (err == nil) != (tt.err == nil) || (err != nil && err.Error() != tt.err.Error()) {
				t.Errorf("expected error %q, got %q", tt.err, err)
			}
		})
	}
}
