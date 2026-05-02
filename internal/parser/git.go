package parser

import (
	"regexp"
	"strings"
)

var (
	gitStatusRe = regexp.MustCompile(`(?i)^git\s+status`)
	gitLogRe    = regexp.MustCompile(`(?i)^git\s+log`)
)

// GitFileEntry represents a changed file in git status.
type GitFileEntry struct {
	Status   string `json:"status"`
	Filename string `json:"filename"`
}

// GitStatusResult is the structured output of `git status`.
type GitStatusResult struct {
	Branch  string         `json:"branch"`
	Files   []GitFileEntry `json:"files"`
	Clean   bool           `json:"clean"`
}

// GitLogEntry represents one commit from `git log`.
type GitLogEntry struct {
	Hash    string `json:"hash"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Message string `json:"message"`
}

// GitStatusParser handles `git status` output.
type GitStatusParser struct{}

func (p *GitStatusParser) Matches(command string) bool {
	return gitStatusRe.MatchString(strings.TrimSpace(command))
}

func (p *GitStatusParser) Parse(output string) (any, error) {
	result := GitStatusResult{}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "On branch ") {
			result.Branch = strings.TrimPrefix(line, "On branch ")
		} else if strings.Contains(line, "nothing to commit") {
			result.Clean = true
		} else if len(line) >= 3 && line[0] != ' ' || (len(line) > 0 && (line[0] == 'M' || line[0] == 'A' || line[0] == 'D' || line[0] == 'R' || line[0] == 'C' || line[0] == '?' || line[0] == 'U')) {
			// Parse porcelain-style lines
			if len(line) >= 3 {
				status := strings.TrimSpace(line[:2])
				filename := strings.TrimSpace(line[3:])
				if filename != "" && status != "" {
					result.Files = append(result.Files, GitFileEntry{
						Status:   status,
						Filename: filename,
					})
				}
			}
		}
	}
	return result, nil
}

// GitLogParser handles `git log` output.
type GitLogParser struct{}

func (p *GitLogParser) Matches(command string) bool {
	return gitLogRe.MatchString(strings.TrimSpace(command))
}

func (p *GitLogParser) Parse(output string) (any, error) {
	var entries []GitLogEntry
	var current *GitLogEntry
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "commit "):
			if current != nil {
				current.Message = strings.TrimSpace(current.Message)
				entries = append(entries, *current)
			}
			current = &GitLogEntry{Hash: strings.TrimPrefix(line, "commit ")}
		case current != nil && strings.HasPrefix(line, "Author:"):
			current.Author = strings.TrimSpace(strings.TrimPrefix(line, "Author:"))
		case current != nil && strings.HasPrefix(line, "Date:"):
			current.Date = strings.TrimSpace(strings.TrimPrefix(line, "Date:"))
		case current != nil && line != "" && !strings.HasPrefix(line, "Merge:"):
			current.Message += strings.TrimSpace(line) + " "
		}
	}
	if current != nil {
		current.Message = strings.TrimSpace(current.Message)
		entries = append(entries, *current)
	}
	return entries, nil
}
