package scan

import (
	"net"
	"regexp"
)

func FindIP(ipre *regexp.Regexp, line string) string {
	matches := ipre.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func validIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
