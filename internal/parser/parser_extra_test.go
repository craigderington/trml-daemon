package parser_test

import (
	"testing"

	"github.com/craigderington/trml-daemon/internal/parser"
)

// ── Edge cases and coverage gaps ─────────────────────────────────────────────

func TestDfParser_EmptyOutput(t *testing.T) {
	p := &parser.DfParser{}
	result, err := p.Parse("")
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	entries := result.([]parser.DfEntry)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty output, got %d", len(entries))
	}
}

func TestDfParser_OnlyHeader(t *testing.T) {
	p := &parser.DfParser{}
	result, err := p.Parse("Filesystem      Size  Used Avail Use% Mounted on")
	if err != nil {
		t.Fatalf("Parse header only: %v", err)
	}
	entries := result.([]parser.DfEntry)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for header-only output, got %d", len(entries))
	}
}

func TestDfParser_MountPointWithSpaces(t *testing.T) {
	output := "Filesystem  Size  Used Avail Use% Mounted on\n" +
		"/dev/sda1    10G    5G    5G  50% /mnt/my disk"
	p := &parser.DfParser{}
	result, _ := p.Parse(output)
	entries := result.([]parser.DfEntry)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].MountedOn != "/mnt/my disk" {
		t.Errorf("expected '/mnt/my disk', got %q", entries[0].MountedOn)
	}
}

func TestDfParser_Matches(t *testing.T) {
	p := &parser.DfParser{}
	cases := []struct {
		cmd   string
		match bool
	}{
		{"df -h", true},
		{"df", true},
		{"df -Th", true},
		{"DF -h", true}, // case insensitive
		{"not-df", false},
		{"grep df", false},
	}
	for _, tc := range cases {
		if got := p.Matches(tc.cmd); got != tc.match {
			t.Errorf("Matches(%q) = %v, want %v", tc.cmd, got, tc.match)
		}
	}
}

func TestPsParser_EmptyOutput(t *testing.T) {
	p := &parser.PsParser{}
	result, err := p.Parse("")
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	entries := result.([]parser.PsEntry)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestPsParser_Matches(t *testing.T) {
	p := &parser.PsParser{}
	cases := []struct {
		cmd   string
		match bool
	}{
		{"ps aux", true},
		{"ps -aux", true},
		{"ps", true},
		{"ps -ef", true},
		{"grep ps", false},
		{"top", false},
	}
	for _, tc := range cases {
		if got := p.Matches(tc.cmd); got != tc.match {
			t.Errorf("Matches(%q) = %v, want %v", tc.cmd, got, tc.match)
		}
	}
}

func TestGitStatusParser_Matches(t *testing.T) {
	p := &parser.GitStatusParser{}
	cases := []struct {
		cmd   string
		match bool
	}{
		{"git status", true},
		{"git status --short", true},
		{"git commit", false},
		{"git log", false},
		{"status", false},
	}
	for _, tc := range cases {
		if got := p.Matches(tc.cmd); got != tc.match {
			t.Errorf("Matches(%q) = %v, want %v", tc.cmd, got, tc.match)
		}
	}
}

func TestGitStatusParser_CleanRepo(t *testing.T) {
	output := "On branch main\nnothing to commit, working tree clean"
	p := &parser.GitStatusParser{}
	result, err := p.Parse(output)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	gs := result.(parser.GitStatusResult)
	if !gs.Clean {
		t.Error("expected Clean=true")
	}
	if gs.Branch != "main" {
		t.Errorf("expected branch 'main', got %q", gs.Branch)
	}
}

func TestGitStatusParser_MultipleChanges(t *testing.T) {
	output := `On branch feature/foo
M  main.go
A  newfile.go
D  old.go
?? untracked.txt`
	p := &parser.GitStatusParser{}
	result, err := p.Parse(output)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	gs := result.(parser.GitStatusResult)
	if gs.Branch != "feature/foo" {
		t.Errorf("expected branch 'feature/foo', got %q", gs.Branch)
	}
	if gs.Clean {
		t.Error("expected Clean=false")
	}
}

func TestGitLogParser_Matches(t *testing.T) {
	p := &parser.GitLogParser{}
	cases := []struct {
		cmd   string
		match bool
	}{
		{"git log", true},
		{"git log --oneline", true},
		{"git log -n 5", true},
		{"git status", false},
		{"git commit", false},
	}
	for _, tc := range cases {
		if got := p.Matches(tc.cmd); got != tc.match {
			t.Errorf("Matches(%q) = %v, want %v", tc.cmd, got, tc.match)
		}
	}
}

func TestGitLogParser_EmptyOutput(t *testing.T) {
	p := &parser.GitLogParser{}
	result, err := p.Parse("")
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	entries := result.([]parser.GitLogEntry)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestLsParser_Matches(t *testing.T) {
	p := &parser.LsParser{}
	cases := []struct {
		cmd   string
		match bool
	}{
		{"ls -la", true},
		{"ls -l", true},
		{"ls -al", true},
		{"ls -la /tmp", true},
		{"ls", false},
		{"ls -a", false},
		{"find . -ls", false},
	}
	for _, tc := range cases {
		if got := p.Matches(tc.cmd); got != tc.match {
			t.Errorf("Matches(%q) = %v, want %v", tc.cmd, got, tc.match)
		}
	}
}

func TestLsParser_EmptyOutput(t *testing.T) {
	p := &parser.LsParser{}
	result, err := p.Parse("")
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	entries := result.([]parser.LsEntry)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestLsParser_FileIsNotDir(t *testing.T) {
	output := `total 8
-rw-r--r--  1 alice staff 100 Apr  1 10:00 README.md`
	p := &parser.LsParser{}
	result, _ := p.Parse(output)
	entries := result.([]parser.LsEntry)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].IsDir {
		t.Error("expected IsDir=false for regular file")
	}
	if entries[0].Name != "README.md" {
		t.Errorf("unexpected name: %s", entries[0].Name)
	}
}

func TestFindParser_CaseAndVariants(t *testing.T) {
	cases := []struct {
		cmd      string
		wantNil  bool
	}{
		{"df -h", false},
		{"df", false},
		{"ps aux", false},
		{"ps", false},
		{"git status", false},
		{"git log", false},
		{"ls -la", false},
		{"ls -l", false},
		{"curl https://example.com", true},
		{"top", true},
		{"uname -a", true},
		{"cat /etc/passwd", true},
	}
	for _, tc := range cases {
		p := parser.FindParser(tc.cmd)
		if tc.wantNil && p != nil {
			t.Errorf("FindParser(%q) should return nil", tc.cmd)
		}
		if !tc.wantNil && p == nil {
			t.Errorf("FindParser(%q) should not return nil", tc.cmd)
		}
	}
}
