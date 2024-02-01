
build:
	go build -o usr/bin/scanban ./cmd/scanban

.PHONY: pkg
pkg:
	ian pkg