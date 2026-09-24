package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ProgressBar displays a rich progress indicator for file transfers.
type ProgressBar struct {
	action      string
	fileName    string
	totalBytes  int64
	current     int64
	startTime   time.Time
	lastTime    time.Time
	lastBytes   int64
	currentRate float64
	isTerm      bool
	finished    bool
	mu          sync.Mutex
}

// NewProgressBar initializes a new progress bar.
func NewProgressBar(action, fileName string, totalBytes int64) *ProgressBar {
	fd := int(os.Stdout.Fd())
	isT := term.IsTerminal(fd) && !IsPlain()
	now := time.Now()

	pb := &ProgressBar{
		action:     action,
		fileName:   fileName,
		totalBytes: totalBytes,
		startTime:  now,
		lastTime:   now,
		isTerm:     isT,
	}

	if isT {
		fmt.Printf("\n%s %s\n\n", action, Bold(fileName))
	} else {
		fmt.Printf("%s %s (%s)...\n", action, fileName, FormatBytes(totalBytes))
	}

	return pb
}

// Update updates the transferred byte count and redraws the progress bar.
func (p *ProgressBar) Update(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.finished {
		return
	}

	p.current = n
	now := time.Now()
	elapsedFromLast := now.Sub(p.lastTime)

	// Calculate rolling speed every 250ms
	if elapsedFromLast >= 250*time.Millisecond {
		bytesDiff := p.current - p.lastBytes
		p.currentRate = float64(bytesDiff) / elapsedFromLast.Seconds()
		p.lastBytes = p.current
		p.lastTime = now
	}

	if !p.isTerm {
		return
	}

	p.render()
}

func (p *ProgressBar) render() {
	var percent float64
	if p.totalBytes > 0 {
		percent = float64(p.current) / float64(p.totalBytes)
		if percent > 1.0 {
			percent = 1.0
		}
	}

	const barWidth = 28
	filled := int(percent * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	empty := barWidth - filled

	fillChar := "█"
	emptyChar := "░"
	bar := strings.Repeat(fillChar, filled) + strings.Repeat(emptyChar, empty)

	speedStr := fmt.Sprintf("%s/s", FormatBytes(int64(p.currentRate)))
	var etaStr string
	if p.currentRate > 0 && p.totalBytes > p.current {
		remainingSecs := float64(p.totalBytes-p.current) / p.currentRate
		if remainingSecs < 60 {
			etaStr = fmt.Sprintf("%.0fs", remainingSecs)
		} else {
			etaStr = fmt.Sprintf("%.0fm %.0fs", remainingSecs/60, float64(int(remainingSecs)%60))
		}
	} else {
		etaStr = "--"
	}

	// Move cursor up 2 lines, clear, and print
	// Line 1: Bar & percentage
	// Line 2: Transferred / Total | Speed | ETA
	fmt.Printf("\033[2A\r\033[K%s  %3.0f%%\n\033[K%s / %s  •  Speed: %s  •  ETA: %s\n",
		Green(bar),
		percent*100,
		FormatBytes(p.current),
		FormatBytes(p.totalBytes),
		speedStr,
		etaStr,
	)
}

// Finish completes the progress bar display.
func (p *ProgressBar) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.finished {
		return
	}
	p.finished = true

	totalElapsed := time.Since(p.startTime).Round(time.Millisecond)
	avgSpeed := float64(p.current) / totalElapsed.Seconds()

	if p.isTerm {
		// Fill the bar completely
		bar := strings.Repeat("█", 28)
		fmt.Printf("\033[2A\r\033[K%s  100%%\n\033[K%s in %s (avg %s/s)\n",
			Green(bar),
			FormatBytes(p.current),
			totalElapsed,
			FormatBytes(int64(avgSpeed)),
		)
	} else {
		fmt.Printf("%s complete: %s in %s (avg %s/s)\n",
			p.action,
			FormatBytes(p.current),
			totalElapsed,
			FormatBytes(int64(avgSpeed)),
		)
	}
}
