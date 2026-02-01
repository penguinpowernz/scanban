package sanitize

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// validIPv4 matches standard IPv4 addresses
	validIPv4 = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

	// validIPv6 matches standard IPv6 addresses
	validIPv6 = regexp.MustCompile(`^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$`)

	// dangerousChars are characters that could be used for injection
	dangerousChars = regexp.MustCompile(`[;&|$\x60<>(){}[\]\\!]`)

	// controlChars are non-printable characters that could cause issues
	controlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// IP validates and sanitizes an IP address to prevent command injection
// Returns empty string if the IP is invalid or contains dangerous characters
func IP(ip string) string {
	if ip == "" {
		return ""
	}

	// Trim whitespace
	ip = strings.TrimSpace(ip)

	// Check for dangerous characters that could be used for command injection
	if dangerousChars.MatchString(ip) {
		return ""
	}

	// Validate IP format (IPv4 or IPv6)
	if validIPv4.MatchString(ip) {
		// Additional validation: check each octet is <= 255
		parts := strings.Split(ip, ".")
		for _, part := range parts {
			var num int
			if _, err := fmt.Sscanf(part, "%d", &num); err != nil || num > 255 {
				return ""
			}
		}
		return ip
	}

	if validIPv6.MatchString(ip) {
		return ip
	}

	return ""
}

// EnvVar sanitizes a string for use in environment variables
// Removes control characters (except tab) and truncates to reasonable length
func EnvVar(s string) string {
	// Remove control characters except tab (\t which is \x09)
	// We remove characters in ranges: \x00-\x08, \x0a-\x1f, \x7f
	var result strings.Builder
	for _, r := range s {
		if (r >= 0x00 && r <= 0x08) || (r >= 0x0a && r <= 0x1f) || r == 0x7f {
			continue // skip control characters except tab
		}
		result.WriteRune(r)
	}
	s = result.String()

	// Truncate to prevent memory exhaustion
	const maxLen = 4096
	if len(s) > maxLen {
		s = s[:maxLen]
	}

	return s
}

// ValidateRegex checks if a regex pattern is safe to compile
// Returns an error if the pattern could cause ReDoS attacks
func ValidateRegex(pattern string) error {
	// Check for catastrophic backtracking patterns
	dangerous := []string{
		`(.*)*`,       // nested quantifiers
		`(.*)+`,       // nested quantifiers
		`(.+)*`,       // nested quantifiers
		`(.+)+`,       // nested quantifiers
		`(a*)*`,       // nested quantifiers on same char
		`(a+)+`,       // nested quantifiers on same char
		`(a|a)*`,      // alternation with overlap
		`(a|ab)*`,     // alternation with overlap
	}

	for _, dangerous := range dangerous {
		if strings.Contains(pattern, dangerous) {
			return errors.New("dangerous regex pattern detected")
		}
	}

	// Try to compile with a reasonable complexity limit
	// Go's regex engine is safe from most ReDoS, but extremely complex
	// patterns can still cause performance issues
	if len(pattern) > 1000 {
		return errors.New("regex pattern too long")
	}

	// Test compilation
	_, err := regexp.Compile(pattern)
	return err
}
