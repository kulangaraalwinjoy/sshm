package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// PromptText prompts for a string input with an optional default value.
func PromptText(label string, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", label, defaultValue)
	} else {
		fmt.Printf("%s: ", label)
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	val := strings.TrimSpace(line)
	if val == "" && defaultValue != "" {
		return defaultValue, nil
	}
	return val, nil
}

// PromptPassword securely prompts for a password or passphrase without echoing characters to terminal.
func PromptPassword(label string) (string, error) {
	fmt.Printf("%s: ", label)

	fd := int(os.Stdin.Fd())
	var passBytes []byte
	var err error

	if term.IsTerminal(fd) {
		passBytes, err = term.ReadPassword(fd)
		fmt.Println() // Add newline after password entry
	} else {
		// Non-terminal fallback (e.g. scripts/pipes)
		reader := bufio.NewReader(os.Stdin)
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return "", readErr
		}
		passBytes = []byte(strings.TrimRight(line, "\r\n"))
	}

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	return string(passBytes), nil
}

// PromptConfirm prompts the user with a Yes/No question.
func PromptConfirm(label string, defaultYes bool) (bool, error) {
	prompt := " [Y/n]: "
	if !defaultYes {
		prompt = " [y/N]: "
	}
	fmt.Printf("%s%s", label, prompt)

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	val := strings.ToLower(strings.TrimSpace(line))
	if val == "" {
		return defaultYes, nil
	}
	return val == "y" || val == "yes", nil
}

// PromptSelect displays numbered options and returns the chosen 0-based index.
func PromptSelect(title string, options []string, defaultIndex int) (int, error) {
	fmt.Println(title)
	for i, opt := range options {
		fmt.Printf("%d. %s\n", i+1, opt)
	}

	prompt := fmt.Sprintf("Select [1-%d]", len(options))
	if defaultIndex >= 0 && defaultIndex < len(options) {
		prompt = fmt.Sprintf("Select [%d]", defaultIndex+1)
	}

	for {
		input, err := PromptText(prompt, "")
		if err != nil {
			return -1, err
		}
		input = strings.TrimSpace(input)
		if input == "" && defaultIndex >= 0 && defaultIndex < len(options) {
			return defaultIndex, nil
		}

		num, err := strconv.Atoi(input)
		if err == nil && num >= 1 && num <= len(options) {
			return num - 1, nil
		}
		fmt.Printf("Invalid selection. Please enter a number between 1 and %d.\n", len(options))
	}
}
