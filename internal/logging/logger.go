package logging

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	mu           sync.RWMutex
	debugEnabled bool
	logOutput    io.Writer = os.Stderr
)

var (
	// Redact sensitive patterns in logs
	privateKeyRegex = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----`)
	passwordRegex   = regexp.MustCompile(`(?i)(password|passphrase|secret|token)\s*[:=]\s*([^\s,;]+)`)
)

// SetDebug enables or disables debug mode.
func SetDebug(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	debugEnabled = enabled
}

// IsDebug returns whether debug logging is enabled.
func IsDebug() bool {
	mu.RLock()
	defer mu.RUnlock()
	return debugEnabled
}

// SetOutput sets the destination writer for log output (defaults to os.Stderr).
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	logOutput = w
}

// Redact scrubs sensitive information such as private keys, passwords, and tokens from strings.
func Redact(msg string) string {
	msg = privateKeyRegex.ReplaceAllString(msg, "[REDACTED PRIVATE KEY]")
	msg = passwordRegex.ReplaceAllString(msg, "$1=[REDACTED]")
	return msg
}

// Debugf prints a redacted debug log line if debug is enabled.
func Debugf(format string, args ...interface{}) {
	mu.RLock()
	enabled := debugEnabled
	w := logOutput
	mu.RUnlock()

	if !enabled {
		return
	}

	raw := fmt.Sprintf(format, args...)
	clean := Redact(raw)
	now := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(w, "[DEBUG] %s %s\n", now, strings.TrimRight(clean, "\n"))
}

// Infof prints an informational log line.
func Infof(format string, args ...interface{}) {
	mu.RLock()
	w := logOutput
	mu.RUnlock()

	raw := fmt.Sprintf(format, args...)
	clean := Redact(raw)
	fmt.Fprintf(w, "[INFO] %s\n", strings.TrimRight(clean, "\n"))
}

// Warnf prints a warning log line.
func Warnf(format string, args ...interface{}) {
	mu.RLock()
	w := logOutput
	mu.RUnlock()

	raw := fmt.Sprintf(format, args...)
	clean := Redact(raw)
	fmt.Fprintf(w, "[WARN] %s\n", strings.TrimRight(clean, "\n"))
}

// Errorf prints an error log line.
func Errorf(format string, args ...interface{}) {
	mu.RLock()
	w := logOutput
	mu.RUnlock()

	raw := fmt.Sprintf(format, args...)
	clean := Redact(raw)
	fmt.Fprintf(w, "[ERROR] %s\n", strings.TrimRight(clean, "\n"))
}
