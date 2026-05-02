package parser

import (
	"regexp"
	"strings"
)

var dfCommandRe = regexp.MustCompile(`(?i)^df(\s|$)`)

// DfEntry represents one line of `df -h` output.
type DfEntry struct {
	Filesystem string `json:"filesystem"`
	Size       string `json:"size"`
	Used       string `json:"used"`
	Avail      string `json:"avail"`
	UsePct     string `json:"use_pct"`
	MountedOn  string `json:"mounted_on"`
}

type DfParser struct{}

func (p *DfParser) Matches(command string) bool {
	return dfCommandRe.MatchString(strings.TrimSpace(command))
}

func (p *DfParser) Parse(output string) (any, error) {
	var entries []DfEntry
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// Skip header line
		if fields[0] == "Filesystem" {
			continue
		}
		entries = append(entries, DfEntry{
			Filesystem: fields[0],
			Size:       fields[1],
			Used:       fields[2],
			Avail:      fields[3],
			UsePct:     fields[4],
			MountedOn:  strings.Join(fields[5:], " "),
		})
	}
	return entries, nil
}
