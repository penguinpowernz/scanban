# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

scanban is a fail2ban alternative written in Go. It scans system logs (files and Docker containers) for patterns indicating malicious activity, extracts IP addresses, and executes ban/unban actions (typically iptables or ipset commands).

## Build and Development Commands

- **Build**: `make build` or `go build -o usr/bin/scanban ./cmd/scanban`
- **Run tests**: `go test ./...`
- **Run single test**: `go test -run TestName ./pkg/packagename`
- **Package**: `make pkg` (uses `ian pkg` tool)

## Testing and Debugging

- **Dry run mode**: `scanban -n -a` - shows what would happen without taking action
- **Test against specific file**: `scanban -n -f /var/log/auth.log`
- **Test with stdin**: `cat /var/log/auth.log | scanban -n -f -`
- **Dump merged config**: `scanban -x -c ./scanban.toml`
- **Test config validity**: `scanban -t -c ./scanban.toml`
- **Verbose output**: Add `-v` flag to any command

## Architecture

### Pipeline Architecture

scanban uses a **handler chain pattern** where each log line flows through multiple handlers in sequence (see cmd/scanban/main.go:112-125):

1. `once.Handle()` - ensures each line is processed only once
2. `eng.Handle()` - runs line through rule engine to match patterns
3. `wl.Handle()` - filters out whitelisted IPs
4. `thresholds.Handle()` - checks if IP has exceeded threshold
5. `actor.Handle()` - executes ban actions
6. `ublist.Handle()` - schedules unban actions
7. `logger.Handle()` - logs the action taken

Each handler receives a `scan.Context` (pkg/scan/ctx.go) which accumulates state as it passes through the pipeline. Handlers check `c.OK()` and return early if previous handlers set an error.

### Key Components

- **Scanner system** (pkg/scan/): Abstracts different input sources
  - File tailing (scan/tail.go, scan/file.go)
  - Docker container logs (scan/docker.go)
  - stdin (scan/stdin.go)
  - All scanners output to a unified channel of `scan.Context`

- **Rule engine** (pkg/rules/): Pattern matching and IP extraction
  - Each rule has regex patterns to match log lines
  - IP extraction regex (configurable per rule)
  - Sets Action, UnbanAction, BanTime, Threshold on matched contexts

- **Threshold system** (pkg/threshold/): Tracks offenses per IP before triggering action

- **Actions** (pkg/actions/): Executes shell commands with variable substitution
  - Commands run via `bash -c` with `$ip` variable replacement
  - Environment variables provided: SB_IP, SB_BANTIME, SB_FILENAME, SB_LINE, SB_NAME, SB_UNBANACTION

- **Unban system** (pkg/unban/): Maintains scheduled unban queue in TOML file
  - Runs async loop checking for IPs to unban
  - Executes unban actions at scheduled times

### Configuration

- Main config: `/etc/scanban.toml` (or specify with `-c`)
- Drop-in configs: `/etc/scanban.d/*.toml` (or specify with `-d`)
- Unban list: `/var/lib/unscanban.toml` (or specify with `-u`)

Config structure (pkg/config/config.go):
- Global settings: bantime, threshold, ip_regex, action, unban_action, do_bans, do_unbans
- `[[rules]]` array: each rule can override global settings
- `[actions]` map: named shell commands
- Rules "compile" by inheriting unset fields from global config (config.go:157-176)

### Important Patterns

- **TOML requires double escaping** in regex: `"\\d+"` not `"\d+"`
- Docker containers specified as: `"docker://container_name"` in files array
- Whitelists support CIDR notation: `"192.168.1.0/24"`
- Context flows through handlers and accumulates state; handlers bail early if `!c.OK()`
