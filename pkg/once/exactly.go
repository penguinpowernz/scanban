package once

import (
	"crypto/md5"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

var seenHashes = make([]string, 0, 50)
var seen = make(map[string]bool)

func Handle(c *scan.Context) {
	md5sum := md5.Sum([]byte(c.Line))
	hashString := string(md5sum[:])

	// Check if the hash has been seen
	if seen[hashString] {
		c.Err("already seen")
		return
	}

	// Add the new hash to the map
	seen[hashString] = true

	// Maintain only 50 hashes in memory
	if len(seen) >= 50 {
		delete(seen, seenHashes[0])
		seenHashes = append(seenHashes[1:], hashString)
	} else {
		seenHashes = append(seenHashes, hashString)
	}
}
