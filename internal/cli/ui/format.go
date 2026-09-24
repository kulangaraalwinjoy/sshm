package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

var (
	plainMode bool
	uiMutex   sync.RWMutex
)

// SetPlain enables or disables plain-text mode (disabling colors and Unicode symbols).
func SetPlain(plain bool) {
	uiMutex.Lock()
	defer uiMutex.Unlock()
	plainMode = plain
}

// IsPlain returns true if plain text mode is set or terminal does not support colors.
func IsPlain() bool {
	uiMutex.RLock()
	defer uiMutex.RUnlock()
	if plainMode {
		return true
	}
	// Fallback to plain if stdout is not a terminal
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return true
	}
	return false
}

// Symbols
func SuccessSymbol() string {
	if IsPlain() {
		return "[OK]"
	}
	return "\033[32m✓\033[0m"
}

func ErrorSymbol() string {
	if IsPlain() {
		return "[ERROR]"
	}
	return "\033[31m✗\033[0m"
}

func WarningSymbol() string {
	if IsPlain() {
		return "[WARN]"
	}
	return "\033[33m⚠\033[0m"
}

func InfoSymbol() string {
	if IsPlain() {
		return "[INFO]"
	}
	return "\033[36mℹ\033[0m"
}

// Color and styling helpers
func Green(s string) string {
	if IsPlain() {
		return s
	}
	return fmt.Sprintf("\033[32m%s\033[0m", s)
}

func Red(s string) string {
	if IsPlain() {
		return s
	}
	return fmt.Sprintf("\033[31m%s\033[0m", s)
}

func Yellow(s string) string {
	if IsPlain() {
		return s
	}
	return fmt.Sprintf("\033[33m%s\033[0m", s)
}

func Cyan(s string) string {
	if IsPlain() {
		return s
	}
	return fmt.Sprintf("\033[36m%s\033[0m", s)
}

func Bold(s string) string {
	if IsPlain() {
		return s
	}
	return fmt.Sprintf("\033[1m%s\033[0m", s)
}

func Dim(s string) string {
	if IsPlain() {
		return s
	}
	return fmt.Sprintf("\033[2m%s\033[0m", s)
}

// PrintSuccess prints a formatted success message.
func PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", SuccessSymbol(), msg)
}

// PrintError prints a formatted error message.
func PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", ErrorSymbol(), msg)
}

// PrintWarning prints a formatted warning message.
func PrintWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", WarningSymbol(), msg)
}

// PrintTable prints tabular data aligned by column widths.
func PrintTable(w io.Writer, headers []string, rows [][]string) {
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Print headers
	for i, h := range headers {
		padding := colWidths[i] - len(h) + 2
		fmt.Fprintf(w, "%s%s", Bold(h), strings.Repeat(" ", padding))
	}
	fmt.Fprintln(w)

	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			padding := colWidths[i] - len(cell) + 2
			fmt.Fprintf(w, "%s%s", cell, strings.Repeat(" ", padding))
		}
		fmt.Fprintln(w)
	}
}

// FormatBytes formats byte counts in human-readable B, KB, MB, GB, etc.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
