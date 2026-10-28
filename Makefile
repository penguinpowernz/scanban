
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o usr/bin/scanban ./cmd/scanban

.PHONY: pkg
pkg:
	ian pkg
