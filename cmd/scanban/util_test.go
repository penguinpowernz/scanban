package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLineChecker(t *testing.T) {
	ach := make(chan Action)
	rule := &RuleConfig{
		Desc:    "WP_discovery",
		Action:  "ipsetblock",
		IpRegex: "for (\\d+.\\d+.\\d+.\\d+) at",
		Pattern: ".*wp-includes.*",
	}
	rule.Compile(&FileConfig{})
	c := makeLineChecker(ach, "production.log", []*RuleConfig{rule})

	badline := `I, [2024-01-31T23:59:55.243160 #145]  INFO -- : [31452379-71f8-4b36-b04b-b27893a6d30b] Started GET "/sign_in/wp/wp-includes/wlwmanifest.xml" for 202.142.126.30 at 2024-01-31 23:59:55 +0000`
	go c(badline)
	var actn Action
	select {
	case actn = <-ach:
	case <-time.After(time.Second / 10):
	}

	assert.Equal(t, "ipsetblock", actn.Name)
	assert.Equal(t, "202.142.126.30", actn.IP)
	assert.Equal(t, "WP_discovery", actn.Desc)
	assert.Equal(t, "production.log", actn.Filename)
	assert.Equal(t, badline, actn.Line)

	goodline := `I, [2024-01-31T15:47:13.555184 #145]  INFO -- : [72fb9373-7063-4f47-bc21-6ce583644e8a] Started GET "/" for 192.168.255.47 at 2024-01-31 15:47:13 +0000`
	go c(goodline)
	actn = Action{}
	select {
	case actn = <-ach:
		t.Errorf("should not have received an action %+v", actn)
	case <-time.After(time.Second / 10):
	}

}

func TestLineCheckerBadIP(t *testing.T) {
	ach := make(chan Action)
	rule := &RuleConfig{
		Desc:    "WP_discovery",
		Action:  "ipsetblock",
		IpRegex: "for (\\d+.\\d+.\\d+.\\d+) at",
		Pattern: ".*wp-includes.*",
	}
	rule.Compile(&FileConfig{})
	c := makeLineChecker(ach, "production.log", []*RuleConfig{rule})

	// 300.142.126.300 is not a valid IP
	badline := `I, [2024-01-31T23:59:55.243160 #145]  INFO -- : [31452379-71f8-4b36-b04b-b27893a6d30b] Started GET "/sign_in/wp/wp-includes/wlwmanifest.xml" for 300.142.126.300 at 2024-01-31 23:59:55 +0000`
	go c(badline)
	select {
	case actn := <-ach:
		t.Errorf("should not have received an action %+v", actn)
	case <-time.After(time.Second / 10):
	}

	// this line don't even have an IP
	badline = `I, [2024-01-31T23:59:55.243160 #145]  INFO -- : [31452379-71f8-4b36-b04b-b27893a6d30b] Started GET "/sign_in/wp/wp-includes/wlwmanifest.xml" for`
	go c(badline)
	select {
	case actn := <-ach:
		t.Errorf("should not have received an action %+v", actn)
	case <-time.After(time.Second / 10):
	}
}

func TestLineCheckerThreshold(t *testing.T) {
	ach := make(chan Action)
	rule := &RuleConfig{
		Desc:      "WP_discovery",
		Action:    "ipsetblock",
		IpRegex:   "for (\\d+.\\d+.\\d+.\\d+) at",
		Pattern:   ".*wp-includes.*",
		Threshold: 1,
	}
	rule.Compile(&FileConfig{})
	c := makeLineChecker(ach, "production.log", []*RuleConfig{rule})

	// the first hit is ignored
	badline := `I, [2024-01-31T23:59:55.243160 #145]  INFO -- : [31452379-71f8-4b36-b04b-b27893a6d30b] Started GET "/sign_in/wp/wp-includes/wlwmanifest.xml" for 202.142.126.30 at 2024-01-31 23:59:55 +0000`
	go c(badline)
	select {
	case actn := <-ach:
		t.Errorf("should not have received an action %+v", actn)
	case <-time.After(time.Second / 10):
	}

	// this is from a different IP
	badline2 := `I, [2024-01-31T23:59:55.243160 #145]  INFO -- : [31452379-71f8-4b36-b04b-b27893a6d30b] Started GET "/sign_in/wp/wp-includes/wlwmanifest.xml" for 202.142.126.31 at 2024-01-31 23:59:55 +0000`
	go c(badline2)
	select {
	case actn := <-ach:
		t.Errorf("should not have received an action %+v", actn)
	case <-time.After(time.Second / 10):
	}

	// the second hit is not ignored
	go c(badline)
	var actn Action
	select {
	case actn = <-ach:
	case <-time.After(time.Second / 10):
	}

	assert.Equal(t, "ipsetblock", actn.Name)
	assert.Equal(t, "202.142.126.30", actn.IP)
	assert.Equal(t, "WP_discovery", actn.Desc)
	assert.Equal(t, "production.log", actn.Filename)
	assert.Equal(t, badline, actn.Line)
}
