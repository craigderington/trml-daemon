package parser

import (
	"regexp"
	"strings"
)

var lsCommandRe = regexp.MustCompile(`(?i)^ls\s+.*-[a-z]*l[a-z]*`)

// LsEntry represents one file from `ls -la` output.
type LsEntry struct {
	Permissions string `json:"permissions"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	Size        string `json:"size"`
	Modified    string `json:"modified"`
	Name        string `json:"name"`
	IsDir       bool   `json:"is_dir"`
}

type LsParser struct{}

func (p *LsParser) Matches(command string) bool {
	cmd := strings.TrimSpace(command)
	// Match `ls -l`, `ls -la`, `ls -al`, etc.
	return lsCommandRe.MatchString(cmd) || regexp.MustCompile(`(?i)^ls\s+-[a-z]*l`).MatchString(cmd)
}

func (p *LsParser) Parse(output string) (any, error) {
	var entries []LsEntry
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "total ") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		perms := fields[0]
		owner := fields[2]
		group := fields[3]
		size := fields[4]
		// Date: fields[5] fields[6] fields[7]
		modified := strings.Join(fields[5:8], " ")
		name := strings.Join(fields[8:], " ")
		entries = append(entries, LsEntry{
			Permissions: perms,
			Owner:       owner,
			Group:       group,
			Size:        size,
			Modified:    modified,
			Name:        name,
			IsDir:       strings.HasPrefix(perms, "d"),
		})
	}
	return entries, nil
}
