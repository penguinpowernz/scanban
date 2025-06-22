package whitelist

import (
	"net"
	"strings"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

func New(ips []string) *List {
	return &List{ips: ips}
}

type List struct {
	ips []string
}

func (wl *List) Handle(c *scan.Context) {
	for _, ip := range wl.ips {
		if strings.Contains(ip, "/") && ipInCIDR(ip, c.IP) {
			c.Err("ip is whitelisted")
			return
		}

		if c.IP == ip {
			c.Err("ip is whitelisted")
			return
		}
	}
}

func ipInCIDR(cidr, ip string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(net.ParseIP(ip))
}
