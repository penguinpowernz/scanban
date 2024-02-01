package main

import (
	"log"
	"net"
)

func ipInCIDR(cidr, ip string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(net.ParseIP(ip))
}

func validIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func makeLineChecker(actionChan chan Action, filename string, rules []*RuleConfig) func(string) {
	return func(line string) {
		for _, rule := range rules {
			if !rule.Match(line) {
				continue
			}

			var ip string
			if ip = rule.FindIP(line); !validIP(ip) {
				log.Printf("WARN: line matched but failed to detect IP: %s", filename)
				log.Printf("WARN: line matched was: %s", line)
				continue
			}

			if ignore := rule.IPHit(ip); ignore {
				log.Printf("WARN: line matched but threshold not hit for %s", ip)
				log.Printf("WARN: line matched was: %s", line)
				continue
			}

			actionChan <- Action{
				Name:     rule.Action,
				IP:       ip,
				Line:     line,
				Filename: filename,
				Desc:     rule.Desc,
			}
		}
	}
}
