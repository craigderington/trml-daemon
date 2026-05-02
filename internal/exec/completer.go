package exec

import (
	"os/exec"
	"strings"
)

// Complete returns up to 30 shell completion candidates for prefix, using
// bash's compgen built-in.
//
// Context rules:
//   - If prefix is the first (or only) token on the line, return command names
//     (executables, builtins, functions, aliases).
//   - Otherwise return file/directory paths; if that yields nothing, fall back
//     to command names (handles "git che<tab>" style subcommand completion).
func Complete(line, prefix string) []string {
	// Determine whether prefix is the first token on the line.
	// Strip the trailing prefix from the line; if what's left has no spaces
	// the user is still on the first word.
	before := strings.TrimSuffix(line, prefix)
	isFirstToken := strings.TrimSpace(before) == ""

	q := shellEscape(prefix)

	var script string
	if isFirstToken {
		script = "compgen -c -- " + q
	} else {
		// File completion; fall back to commands if nothing found.
		script = "{ compgen -f -- " + q + "; } 2>/dev/null"
	}
	script += " 2>/dev/null | sort -u | head -30"

	out, err := exec.Command("bash", "-c", script).Output()
	if err != nil || len(out) == 0 {
		if !isFirstToken {
			// Try command completion as fallback (e.g. git sub-commands typed via PATH)
			script2 := "compgen -c -- " + q + " 2>/dev/null | sort -u | head -30"
			out, err = exec.Command("bash", "-c", script2).Output()
			if err != nil || len(out) == 0 {
				return nil
			}
		} else {
			return nil
		}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	seen := make(map[string]bool, len(lines))
	results := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !seen[l] {
			seen[l] = true
			results = append(results, l)
		}
	}
	return results
}

// shellEscape wraps s in single quotes, escaping any embedded single quotes.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
