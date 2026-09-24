package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "password: mysecretpassword",
			expected: "password=[REDACTED]",
		},
		{
			input:    "passphrase= sensitive_data_here",
			expected: "passphrase=[REDACTED]",
		},
		{
			input:    "Connecting to user@example.com with token: xyz12345",
			expected: "Connecting to user@example.com with token=[REDACTED]",
		},
		{
			input:    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
		},
	}

	for _, tt := range tests {
		got := Redact(tt.input)
		if !strings.Contains(got, "[REDACTED") {
			t.Errorf("Redact(%q) = %q; expected to contain [REDACTED", tt.input, got)
		}
	}
}

func TestLoggerOutput(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetDebug(true)

	Debugf("password: secret123 on host %s", "10.0.0.1")

	output := buf.String()
	if strings.Contains(output, "secret123") {
		t.Fatalf("Log contains unredacted password: %s", output)
	}
	if !strings.Contains(output, "password=[REDACTED]") {
		t.Fatalf("Log missing redacted placeholder: %s", output)
	}
}
