package parser_test

import (
	"testing"

	"github.com/craigderington/trml-daemon/internal/parser"
)

func TestDfParser(t *testing.T) {
	output := `Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   20G   28G  42% /
tmpfs           7.8G     0  7.8G   0% /dev/shm`

	p := parser.FindParser("df -h")
	if p == nil {
		t.Fatal("FindParser returned nil for 'df -h'")
	}
	result, err := p.Parse(output)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	entries, ok := result.([]parser.DfEntry)
	if !ok {
		t.Fatalf("expected []DfEntry, got %T", result)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Filesystem != "/dev/sda1" {
		t.Errorf("unexpected filesystem: %s", entries[0].Filesystem)
	}
	if entries[0].UsePct != "42%" {
		t.Errorf("unexpected use%%: %s", entries[0].UsePct)
	}
}

func TestPsParser(t *testing.T) {
	output := `USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0  12345  1234 ?        Ss   10:00   0:00 /sbin/init
alice       1234  1.5  0.5  98765  5432 pts/0    S+   10:05   0:01 bash`

	p := parser.FindParser("ps aux")
	if p == nil {
		t.Fatal("FindParser returned nil for 'ps aux'")
	}
	result, err := p.Parse(output)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	entries, ok := result.([]parser.PsEntry)
	if !ok {
		t.Fatalf("expected []PsEntry, got %T", result)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].User != "root" {
		t.Errorf("unexpected user: %s", entries[0].User)
	}
}

func TestGitStatusParser(t *testing.T) {
	output := `On branch main
M  app.go
?? newfile.txt`

	p := parser.FindParser("git status")
	if p == nil {
		t.Fatal("FindParser returned nil for 'git status'")
	}
	result, err := p.Parse(output)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	gs, ok := result.(parser.GitStatusResult)
	if !ok {
		t.Fatalf("expected GitStatusResult, got %T", result)
	}
	if gs.Branch != "main" {
		t.Errorf("expected branch 'main', got %q", gs.Branch)
	}
}

func TestGitLogParser(t *testing.T) {
	output := `commit abc123def456
Author: Alice <alice@example.com>
Date:   Mon Apr 1 10:00:00 2026 +0000

    Initial commit

commit 789xyz
Author: Bob <bob@example.com>
Date:   Tue Apr 2 11:00:00 2026 +0000

    Add feature`

	p := parser.FindParser("git log --oneline")
	if p == nil {
		// git log --oneline doesn't match the git log pattern - use exact
		p = parser.FindParser("git log")
	}
	if p == nil {
		t.Fatal("FindParser returned nil for 'git log'")
	}
	result, err := p.Parse(output)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	entries, ok := result.([]parser.GitLogEntry)
	if !ok {
		t.Fatalf("expected []GitLogEntry, got %T", result)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Hash != "abc123def456" {
		t.Errorf("unexpected hash: %s", entries[0].Hash)
	}
}

func TestLsParser(t *testing.T) {
	output := `total 48
drwxr-xr-x  5 alice staff  160 Apr  1 10:00 .
drwxr-xr-x 20 alice staff  640 Apr  1 09:00 ..
-rw-r--r--  1 alice staff 1234 Apr  1 10:00 main.go`

	p := parser.FindParser("ls -la")
	if p == nil {
		t.Fatal("FindParser returned nil for 'ls -la'")
	}
	result, err := p.Parse(output)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	entries, ok := result.([]parser.LsEntry)
	if !ok {
		t.Fatalf("expected []LsEntry, got %T", result)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
	if !entries[0].IsDir {
		t.Errorf("expected first entry to be a directory")
	}
	if entries[2].Name != "main.go" {
		t.Errorf("unexpected name: %s", entries[2].Name)
	}
}

func TestNoMatchReturnsNil(t *testing.T) {
	p := parser.FindParser("curl https://example.com")
	if p != nil {
		t.Errorf("expected nil parser for 'curl', got %T", p)
	}
}
