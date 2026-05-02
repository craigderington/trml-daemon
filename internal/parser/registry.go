package parser

// Parser inspects a command string and, if it matches, parses the command output.
type Parser interface {
	// Matches returns true if this parser handles the given command.
	Matches(command string) bool
	// Parse converts raw command output into a structured value.
	Parse(output string) (any, error)
}

var defaultRegistry []Parser

func init() {
	defaultRegistry = []Parser{
		&DfParser{},
		&PsParser{},
		&GitStatusParser{},
		&GitLogParser{},
		&LsParser{},
	}
}

// FindParser returns the first parser that matches command, or nil.
func FindParser(command string) Parser {
	for _, p := range defaultRegistry {
		if p.Matches(command) {
			return p
		}
	}
	return nil
}
