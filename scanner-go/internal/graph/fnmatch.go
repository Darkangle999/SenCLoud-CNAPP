package graph

import (
	"regexp"
	"strings"
	"sync"
)

// Python's fnmatch, not Go's path.Match.
//
// This is not a stylistic preference. path.Match treats '/' as a separator that
// '*' will not cross, and every identifier the graph matches is an ARN full of
// slashes: under path.Match the grant "arn:aws:s3:::data-*" would fail to match
// "arn:aws:s3:::data-prod/objects", and an IAM grant that really does confer
// access would read as no access. Silently narrowing a permission match makes
// the engine miss attack paths, so fnmatch's semantics are reproduced exactly.
//
// Reproduced from CPython's fnmatch.translate: '*' -> '.*', '?' -> '.',
// '[seq]' -> character class, '[!seq]' -> negated class, everything else
// literal, whole-string match with DOTALL.

var (
	patternCacheMu sync.RWMutex
	patternCache   = map[string]*regexp.Regexp{}
)

// compilePattern returns the compiled form of one fnmatch pattern. Patterns
// repeat heavily across an account (the same grant tested against thousands of
// resources), so they are cached for the life of the process.
func compilePattern(pattern string) *regexp.Regexp {
	patternCacheMu.RLock()
	compiled, ok := patternCache[pattern]
	patternCacheMu.RUnlock()
	if ok {
		return compiled
	}

	compiled = regexp.MustCompile(translate(pattern))

	patternCacheMu.Lock()
	patternCache[pattern] = compiled
	patternCacheMu.Unlock()
	return compiled
}

// translate converts an fnmatch pattern to an anchored Go regexp source.
func translate(pattern string) string {
	var out strings.Builder
	out.WriteString(`(?s)\A`)

	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch c := runes[i]; c {
		case '*':
			out.WriteString(".*")
		case '?':
			out.WriteString(".")
		case '[':
			// Find the closing bracket. An unterminated '[' is a literal, which
			// is what CPython does too.
			j := i + 1
			if j < len(runes) && (runes[j] == '!' || runes[j] == '^') {
				j++
			}
			if j < len(runes) && runes[j] == ']' {
				j++
			}
			for j < len(runes) && runes[j] != ']' {
				j++
			}
			if j >= len(runes) {
				out.WriteString(regexp.QuoteMeta("["))
				continue
			}
			class := string(runes[i+1 : j])
			i = j
			// CPython maps a leading '!' to a negated class and leaves a
			// literal '^' as a member, so '^' must be escaped when it leads.
			switch {
			case strings.HasPrefix(class, "!"):
				class = "^" + escapeClass(class[1:])
			case strings.HasPrefix(class, "^"):
				class = `\^` + escapeClass(class[1:])
			default:
				class = escapeClass(class)
			}
			out.WriteString("[" + class + "]")
		default:
			out.WriteString(regexp.QuoteMeta(string(c)))
		}
	}

	out.WriteString(`\z`)
	return out.String()
}

// escapeClass escapes the characters that would otherwise change the meaning of
// a regexp character class, leaving ranges ('a-z') intact.
func escapeClass(class string) string {
	var out strings.Builder
	for _, c := range class {
		if c == '\\' || c == ']' || c == '^' {
			out.WriteRune('\\')
		}
		out.WriteRune(c)
	}
	return out.String()
}

// fnmatchCase reports whether name matches pattern, case-sensitively.
func fnmatchCase(name, pattern string) bool {
	return compilePattern(pattern).MatchString(name)
}
