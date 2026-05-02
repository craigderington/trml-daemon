package parser

import (
	"regexp"
	"strings"
)

var psCommandRe = regexp.MustCompile(`(?i)^ps(\s|$)`)

// PsEntry represents one process from `ps aux` output.
type PsEntry struct {
	User    string `json:"user"`
	PID     string `json:"pid"`
	CPUPct  string `json:"cpu_pct"`
	MemPct  string `json:"mem_pct"`
	Command string `json:"command"`
}

type PsParser struct{}

func (p *PsParser) Matches(command string) bool {
	return psCommandRe.MatchString(strings.TrimSpace(command))
}

func (p *PsParser) Parse(output string) (any, error) {
	var entries []PsEntry
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		// Skip header
		if fields[0] == "USER" || fields[0] == "UID" {
			continue
		}
		entries = append(entries, PsEntry{
			User:    fields[0],
			PID:     fields[1],
			CPUPct:  fields[2],
			MemPct:  fields[3],
			Command: strings.Join(fields[10:], " "),
		})
	}
	return entries, nil
}
