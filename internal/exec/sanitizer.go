package exec

import (
	"fmt"
	"regexp"
	"strings"
)

// ── Aliases ───────────────────────────────────────────────────────────────────

var aliasMap = map[string]string{
	"ll":   "ls -la",
	"la":   "ls -la",
	"l":    "ls -CF",
	"catn": "cat -n",
}

// AliasExpand returns the expanded command for known aliases, or the original
// input unchanged if it is not a recognized alias. It handles trailing arguments:
// "ll -a" → "ls -la -a".
func AliasExpand(cmd string) string {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return trimmed
	}

	parts := strings.Fields(trimmed)
	lowerFirst := strings.ToLower(parts[0])

	if expanded, ok := aliasMap[lowerFirst]; ok {
		// Expand the alias and append any trailing arguments.
		if len(parts) > 1 {
			return expanded + " " + strings.Join(parts[1:], " ")
		}
		return expanded
	}
	return cmd
}

// ── Dangerous patterns (always blocked) ───────────────────────────────────────

var dangerousPatterns = []*regexp.Regexp{
	// rm -rf / or rm -rf /*
	regexp.MustCompile(`(?i)\brm\s+.*-r[fF].*/\s*$`),
	regexp.MustCompile(`(?i)\brm\s+.*-r[fF]\s+/`),

	// dd to root devices
	regexp.MustCompile(`(?i)\bdd\b.*if=/dev/(zero|urandom)`),

	// mkfs, fdisk, wipefs on system partitions
	regexp.MustCompile(`(?i)\b(mkfs|fdisk|wipefs)\b`),

	// pipes to curl/wget/nc (data exfiltration) — pipe followed by download or network tools
	regexp.MustCompile(`\|\s*(curl|wget)\b`),
	regexp.MustCompile(`\|\s*nc\b`),
	regexp.MustCompile(`\|\s*ncat\b`),

	// redirecting output to system directories
	regexp.MustCompile(`>\s*/(etc|usr|bin|sbin)/`),
	regexp.MustCompile(`2?>\s*/(etc|usr|bin|sbin)/`),

	// sudo, su (standalone or as first command)
	regexp.MustCompile(`(?i)^(\s*|\|\s*)\bsudo\b`),
	regexp.MustCompile(`(?i)^(\s*|\|\s*)\bsu\b\s`),
	regexp.MustCompile(`(?i)^(\s*|\|\s*)\bpasswd\b`),

	// && or ; followed by dangerous patterns
	regexp.MustCompile(`&&\s*(rm|dd|mkfs|fdisk|wipefs|sudo|su|chmod\s+777)\b`),
	regexp.MustCompile(`;\s*(rm|dd|mkfs|fdisk|wipefs|sudo|su|chmod\s+777)\b`),

	// base64 decode piped to sh/bash
	regexp.MustCompile(`(?i)\bbase64\b.*\|\s*(sh|bash)\b`),
	regexp.MustCompile(`(?i)\b(base64|--decode|-d)\b.*\|\s*(sh|bash)\b`),

	// eval without arguments (eval is dangerous by nature)
	regexp.MustCompile(`(?i)^(\s*|\|\s*)\beval\b`),

	// exec without arguments (exec as a command, not exec.CommandContext)
	regexp.MustCompile(`(?i)^(\s*|\|\s*)\bexec\b\s*$`),
}

// ── Allowlist ─────────────────────────────────────────────────────────────────

// defaultAllowedCommands is the built-in set of permitted commands.
// Users can extend this at runtime via AddExtraAllowedCommands (from the config file).
var defaultAllowedCommands = map[string]bool{
	// Basic filesystem
	"ls": true, "cat": true, "head": true, "tail": true, "wc": true,
	"find": true, "stat": true, "file": true, "du": true, "df": true,
	"pwd": true, "whoami": true, "hostname": true, "uname": true,
	"ln": true, "readlink": true, "realpath": true, "basename": true, "dirname": true,

	// Archives & compression
	"tar": true, "gzip": true, "gunzip": true, "zip": true, "unzip": true,
	"bzip2": true, "bunzip2": true, "xz": true, "zstd": true,

	// Process/system
	"ps": true, "top": true, "uptime": true, "free": true, "mount": true,
	"netstat": true, "ss": true, "ip": true, "ifconfig": true, "route": true,
	"ping": true, "traceroute": true, "lsof": true,
	"pgrep": true, "kill": true, "killall": true,
	"env": true, "printenv": true, "which": true, "whereis": true, "type": true,
	"date": true, "cal": true, "watch": true, "time": true, "timeout": true,

	// Services / init systems
	"systemctl": true, "launchctl": true, "service": true, "apachectl": true,
	"nginx": true, "dmesg": true, "journalctl": true, "sysctl": true,

	// Git subcommands (handled separately)
	"git": true,

	// Text processing
	"grep": true, "awk": true, "sed": true, "sort": true, "uniq": true,
	"cut": true, "tr": true, "tee": true, "xargs": true,
	"diff": true, "patch": true, "less": true, "more": true,
	"jq": true, "yq": true, "column": true, "fmt": true,

	// Package managers & build tools
	"apt": true, "apt-get": true, "dpkg": true, "rpm": true, "yum": true, "dnf": true,
	"brew": true, "make": true, "cmake": true, "ninja": true,
	"pip": true, "pip3": true, "pipenv": true, "poetry": true,
	"npm": true, "npx": true, "yarn": true, "pnpm": true,
	"go": true, "cargo": true,

	// Scripting runtimes
	"python": true, "python3": true, "node": true, "nodejs": true,
	"ruby": true, "perl": true, "php": true,

	// Network
	"curl": true, "wget": true, "nc": true, "ncat": true,
	"ssh": true, "scp": true, "rsync": true,
	"dig": true, "nslookup": true, "host": true,
	"openssl": true,

	// Containers / cloud
	"docker": true, "docker-compose": true,
	"kubectl": true, "helm": true,
	"aws": true, "gcloud": true, "az": true,
	"terraform": true, "ansible": true,

	// Text editors (will fail without PTY, but not harmful)
	"vim": true, "nano": true, "emacs": true, "code": true,

	// File operations (rm restrictions checked separately)
	"mkdir": true, "touch": true, "cp": true, "mv": true, "rm": true,
	"chmod": true, "chown": true,

	// Common shell builtins / utilities
	"echo": true, "printf": true, "sleep": true, "true": true, "false": true,
	"test": true, "read": true, "source": true, "export": true, "unset": true,
	"exit": true, "nohup": true,
}

// allowedCommands is the active set, combining defaults with any extras from config.
// Initialised from defaultAllowedCommands; call AddExtraAllowedCommands to extend.
var allowedCommands = func() map[string]bool {
	m := make(map[string]bool, len(defaultAllowedCommands))
	for k, v := range defaultAllowedCommands {
		m[k] = v
	}
	return m
}()

// AddExtraAllowedCommands merges additional command names into the active allowlist.
// Call this once at startup with the user-supplied list from the config file.
func AddExtraAllowedCommands(extras []string) {
	for _, cmd := range extras {
		if cmd != "" {
			allowedCommands[strings.ToLower(cmd)] = true
		}
	}
}

// gitSubcommands lists allowed git subcommands.
var gitSubcommands = map[string]bool{
	// Read-only / safe
	"status": true, "log": true, "diff": true, "branch": true,
	"remote": true, "show": true, "stash": true, "tag": true,
	"describe": true, "shortlog": true, "blame": true, "annotate": true,
	"ls-files": true, "ls-remote": true, "rev-parse": true, "rev-list": true,
	"submodule": true, "worktree": true, "config": true,
	// Common write operations
	"fetch": true, "pull": true, "push": true,
	"checkout": true, "switch": true, "restore": true,
	"add": true, "commit": true, "reset": true, "revert": true,
	"merge": true, "rebase": true, "cherry-pick": true,
	"clone": true, "init": true,
}

// ── rm restrictions ───────────────────────────────────────────────────────────

var rmDangerousFlags = regexp.MustCompile(`(?i)\brm\b.*-r[fF]`)
var rmRootTarget = regexp.MustCompile(`(?i)\brm\b.*/\s*$`)

// ── Public API ────────────────────────────────────────────────────────────────

// ValidateCommand checks whether a command string is safe to execute. It first
// expands known aliases, then verifies the command (and any subcommands) against
// the allowlist, and finally scans for dangerous patterns that are always blocked.
func ValidateCommand(cmd string) error {
	if cmd == "" {
		return fmt.Errorf("empty command")
	}

	// Truncate extremely long commands to avoid DoS in regex processing.
	const maxLen = 4096
	if len(cmd) > maxLen {
		cmd = cmd[:maxLen]
	}

	// Step 1: Expand aliases.
	cmd = AliasExpand(cmd)

	// Step 2: Check for dangerous patterns (always blocked).
	for _, re := range dangerousPatterns {
		if re.MatchString(cmd) {
			return fmt.Errorf("this command contains a dangerous pattern and cannot run")
		}
	}

	// Step 3: Extract the base command (first word).
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return fmt.Errorf("no command found")
	}
	baseCmd := parts[0]

	// Case-insensitive lookup.
	lowerBase := strings.ToLower(baseCmd)

	// Special handling for git subcommands.
	if lowerBase == "git" && len(parts) >= 2 {
		subcmd := strings.ToLower(parts[1])
		if !gitSubcommands[subcmd] {
			return fmt.Errorf("'git %s' is not an allowed subcommand — try: status, log, diff, branch, remote, show, stash, tag", parts[1])
		}
		// Check for dangerous flags on git commands.
		for _, flag := range parts[2:] {
			lowerFlag := strings.ToLower(flag)
			if lowerFlag == "-f" || lowerFlag == "--force" {
				return fmt.Errorf("'git %s --force' is not allowed", subcmd)
			}
		}
		return nil
	}

	// Check if the base command is in the allowlist.
	if !allowedCommands[lowerBase] {
		return fmt.Errorf("'%s' is not an allowed command", baseCmd)
	}

	// Special restriction for rm: no -rf / or similar destructive flags.
	if lowerBase == "rm" {
		for _, flag := range parts[1:] {
			if rmDangerousFlags.MatchString("rm " + flag) {
				return fmt.Errorf("'rm' with recursive/force flags is not allowed")
			}
		}
		if rmRootTarget.MatchString(cmd) {
			return fmt.Errorf("'rm' targeting the root directory is not allowed")
		}
	}

	return nil
}

// SanitizeCommand normalizes a command string for safe execution. It expands
// aliases, trims whitespace, and returns the sanitized form. If validation fails,
// an error is returned alongside the original (unsanitized) input.
func SanitizeCommand(cmd string) (string, error) {
	if err := ValidateCommand(cmd); err != nil {
		return cmd, err
	}

	sanitized := strings.TrimSpace(cmd)
	sanitized = AliasExpand(sanitized)

	return sanitized, nil
}
