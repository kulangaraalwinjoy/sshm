package sftp

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/kulangaraalwinjoy/sshm/internal/cli/ui"
	"golang.org/x/term"
)

// FileBrowser provides a state machine for browsing and managing files over SFTP.
// It is designed to be fully headless and reusable by both CLI and future GUI frontends.
type FileBrowser struct {
	ProfileName string
	SFTP        *SFTPClient
	CurrentPath string
	Entries     []os.FileInfo
	Cursor      int
	PageSize    int
}

// NewFileBrowser initializes a FileBrowser starting at the remote default directory.
func NewFileBrowser(profileName string, client *SFTPClient, initialPath string) (*FileBrowser, error) {
	if initialPath == "" {
		wd, err := client.GetWD()
		if err != nil || wd == "" {
			initialPath = "/"
		} else {
			initialPath = wd
		}
	}

	fb := &FileBrowser{
		ProfileName: profileName,
		SFTP:        client,
		CurrentPath: initialPath,
		Cursor:      0,
		PageSize:    15,
	}

	if err := fb.Refresh(); err != nil {
		// Fallback to root /
		fb.CurrentPath = "/"
		if rErr := fb.Refresh(); rErr != nil {
			return nil, err
		}
	}

	return fb, nil
}

// Refresh reloads the directory contents from the server.
func (b *FileBrowser) Refresh() error {
	entries, err := b.SFTP.ListDirectory(b.CurrentPath)
	if err != nil {
		return err
	}
	b.Entries = entries
	if b.Cursor >= len(b.Entries) {
		b.Cursor = len(b.Entries) - 1
	}
	if b.Cursor < 0 {
		b.Cursor = 0
	}
	return nil
}

// Enter descends into the selected directory.
func (b *FileBrowser) Enter() error {
	if len(b.Entries) == 0 || b.Cursor >= len(b.Entries) {
		return nil
	}

	selected := b.Entries[b.Cursor]
	if selected.IsDir() {
		b.CurrentPath = path.Join(b.CurrentPath, selected.Name())
		b.Cursor = 0
		return b.Refresh()
	}
	return nil
}

// Up ascends to the parent directory.
func (b *FileBrowser) Up() error {
	parent := path.Dir(b.CurrentPath)
	if parent == b.CurrentPath {
		return nil // already at root
	}
	b.CurrentPath = parent
	b.Cursor = 0
	return b.Refresh()
}

// Selected returns the currently focused file/directory info.
func (b *FileBrowser) Selected() (os.FileInfo, bool) {
	if len(b.Entries) == 0 || b.Cursor >= len(b.Entries) {
		return nil, false
	}
	return b.Entries[b.Cursor], true
}

// SelectedPath returns the full remote path of the focused item.
func (b *FileBrowser) SelectedPath() string {
	item, ok := b.Selected()
	if !ok {
		return ""
	}
	return path.Join(b.CurrentPath, item.Name())
}

// Mkdir creates a directory in the current remote path.
func (b *FileBrowser) Mkdir(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("directory name cannot be empty")
	}
	target := path.Join(b.CurrentPath, name)
	if err := b.SFTP.Mkdir(target); err != nil {
		return err
	}
	return b.Refresh()
}

// DeleteSelected deletes the selected file or directory recursively.
func (b *FileBrowser) DeleteSelected() error {
	target := b.SelectedPath()
	if target == "" {
		return fmt.Errorf("no item selected")
	}
	if err := b.SFTP.RemoveAll(target); err != nil {
		return err
	}
	return b.Refresh()
}

// RenameSelected renames the selected item.
func (b *FileBrowser) RenameSelected(newName string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return fmt.Errorf("new name cannot be empty")
	}
	target := b.SelectedPath()
	if target == "" {
		return fmt.Errorf("no item selected")
	}
	newTarget := path.Join(b.CurrentPath, newName)
	if err := b.SFTP.Rename(target, newTarget); err != nil {
		return err
	}
	return b.Refresh()
}

// RunInteractive runs the interactive terminal file manager.
func (b *FileBrowser) RunInteractive(
	uploadHandler func(localFile, remoteDest string) error,
	downloadHandler func(remoteFile, localDest string) error,
) error {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return fmt.Errorf("interactive file manager requires a terminal")
	}

	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("failed to set terminal to raw mode: %w", err)
	}
	defer func() {
		_ = term.Restore(stdinFd, oldState)
		fmt.Print("\033[?25h") // Ensure cursor is shown
	}()

	fmt.Print("\033[?25l") // Hide cursor

	statusMsg := ""

	for {
		b.render(statusMsg)
		statusMsg = ""

		// Read raw input
		buf := make([]byte, 3)
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}

		key := buf[0]

		// Handle ANSI arrow escape sequences (ESC [ A / B)
		if n >= 3 && buf[0] == 27 && buf[1] == '[' {
			switch buf[2] {
			case 'A': // Up arrow
				if b.Cursor > 0 {
					b.Cursor--
				}
				continue
			case 'B': // Down arrow
				if b.Cursor < len(b.Entries)-1 {
					b.Cursor++
				}
				continue
			}
		}

		switch key {
		case 'q', 'Q', 3: // 'q' or Ctrl+C to quit
			return nil

		case 'k', 'K': // Up
			if b.Cursor > 0 {
				b.Cursor--
			}

		case 'j', 'J': // Down
			if b.Cursor < len(b.Entries)-1 {
				b.Cursor++
			}

		case 13, 10: // Enter (open directory)
			if err := b.Enter(); err != nil {
				statusMsg = ui.Red(fmt.Sprintf("Error opening directory: %v", err))
			}

		case '-', 127, 8: // '-' or Backspace (go to parent directory)
			if err := b.Up(); err != nil {
				statusMsg = ui.Red(fmt.Sprintf("Error going up: %v", err))
			}

		case 'r', 'R': // Rename
			_ = term.Restore(stdinFd, oldState)
			fmt.Print("\033[?25h\n")
			newName, pErr := ui.PromptText("New name", "")
			if pErr == nil && newName != "" {
				if rErr := b.RenameSelected(newName); rErr != nil {
					statusMsg = ui.Red(fmt.Sprintf("Rename failed: %v", rErr))
				} else {
					statusMsg = ui.Green("Renamed successfully.")
				}
			}
			oldState, _ = term.MakeRaw(stdinFd)
			fmt.Print("\033[?25l")

		case 'n', 'N': // New directory
			_ = term.Restore(stdinFd, oldState)
			fmt.Print("\033[?25h\n")
			dirName, pErr := ui.PromptText("Directory name", "")
			if pErr == nil && dirName != "" {
				if mErr := b.Mkdir(dirName); mErr != nil {
					statusMsg = ui.Red(fmt.Sprintf("Mkdir failed: %v", mErr))
				} else {
					statusMsg = ui.Green("Directory created.")
				}
			}
			oldState, _ = term.MakeRaw(stdinFd)
			fmt.Print("\033[?25l")

		case 'x', 'X': // Delete
			if item, ok := b.Selected(); ok {
				_ = term.Restore(stdinFd, oldState)
				fmt.Print("\033[?25h\n")
				confirmPrompt := fmt.Sprintf("Delete remote %q permanently?", item.Name())
				confirmed, cErr := ui.PromptConfirm(confirmPrompt, false)
				if cErr == nil && confirmed {
					if dErr := b.DeleteSelected(); dErr != nil {
						statusMsg = ui.Red(fmt.Sprintf("Delete failed: %v", dErr))
					} else {
						statusMsg = ui.Green("Deleted successfully.")
					}
				}
				oldState, _ = term.MakeRaw(stdinFd)
				fmt.Print("\033[?25l")
			}

		case 'u', 'U': // Upload
			if uploadHandler != nil {
				_ = term.Restore(stdinFd, oldState)
				fmt.Print("\033[?25h\n")
				localFile, pErr := ui.PromptText("Local file/folder to upload", "")
				if pErr == nil && localFile != "" {
					if uErr := uploadHandler(localFile, b.CurrentPath); uErr != nil {
						statusMsg = ui.Red(fmt.Sprintf("Upload failed: %v", uErr))
					} else {
						statusMsg = ui.Green("Upload complete.")
						_ = b.Refresh()
					}
				}
				oldState, _ = term.MakeRaw(stdinFd)
				fmt.Print("\033[?25l")
			}

		case 'd', 'D': // Download
			if downloadHandler != nil {
				if item, ok := b.Selected(); ok {
					_ = term.Restore(stdinFd, oldState)
					fmt.Print("\033[?25h\n")
					localDest, pErr := ui.PromptText("Local download destination path", ".")
					if pErr == nil && localDest != "" {
						remoteSrc := path.Join(b.CurrentPath, item.Name())
						if dErr := downloadHandler(remoteSrc, localDest); dErr != nil {
							statusMsg = ui.Red(fmt.Sprintf("Download failed: %v", dErr))
						} else {
							statusMsg = ui.Green("Download complete.")
						}
					}
					oldState, _ = term.MakeRaw(stdinFd)
					fmt.Print("\033[?25l")
				}
			}
		}
	}

	return nil
}

func (b *FileBrowser) render(statusMsg string) {
	var sb strings.Builder
	// Clear screen & move to top-left
	sb.WriteString("\033[H\033[2J")

	// Header
	header := fmt.Sprintf("%s:%s", ui.Bold(b.ProfileName), ui.Cyan(b.CurrentPath))
	sb.WriteString(fmt.Sprintf("%s\n\n", header))

	if len(b.Entries) == 0 {
		sb.WriteString("  (empty directory)\n")
	} else {
		// Calculate viewport window
		start := 0
		if b.Cursor >= b.PageSize {
			start = b.Cursor - b.PageSize + 1
		}
		end := start + b.PageSize
		if end > len(b.Entries) {
			end = len(b.Entries)
		}

		if start > 0 {
			sb.WriteString(ui.Dim("  ▲ ...\n"))
		}

		for i := start; i < end; i++ {
			entry := b.Entries[i]
			cursorMark := "  "
			if i == b.Cursor {
				cursorMark = ui.Green("> ")
			}

			name := entry.Name()
			if entry.IsDir() {
				name = ui.Bold(name + "/")
			} else {
				name = fmt.Sprintf("%-28s %10s", name, ui.Dim(ui.FormatBytes(entry.Size())))
			}

			sb.WriteString(fmt.Sprintf("%s%s\n", cursorMark, name))
		}

		if end < len(b.Entries) {
			sb.WriteString(ui.Dim("  ▼ ...\n"))
		}
	}

	sb.WriteString("\n" + ui.Dim("Commands:") + "\n")
	sb.WriteString("Enter: Open dir | -: Parent dir | U: Upload | D: Download\n")
	sb.WriteString("R: Rename       | X: Delete     | N: New dir| Q: Quit\n")

	if statusMsg != "" {
		sb.WriteString(fmt.Sprintf("\n%s\n", statusMsg))
	}

	writer := bufio.NewWriter(os.Stdout)
	_, _ = writer.WriteString(sb.String())
	_ = writer.Flush()
}
