# scanban

A lightweight, fast alternative to fail2ban written in Go.

Scanban monitors system logs for patterns that indicate malicious activity (brute force attempts, exploit scanning, etc.), extracts offending IP addresses and automatically bans them for a configurable period of time. It works by tailing log files and Docker container logs in real-time, matching lines against regular expression patterns, and executing custom actions (fully configurable, typically iptables or ipset commands) to block attackers.

With the correct config you can block attackers during recon, before an attack even takes place by
assuming that if they are scanning for one exploit, they may scan for others.

## Features

- **Easy configuration** - Simple TOML format with sensible defaults
- **Regular expression based matching** - Flexible pattern matching for any log format
- **Multiple log sources** - Tail files and Docker container logs simultaneously
- **Time-based banning** - Automatically ban and unban IPs after a specified duration
- **Customizable actions** - Execute any shell command for ban/unban operations
- **Threshold support** - Require multiple offenses before banning
- **Whitelisting** - Never ban specific IPs or subnets
- **Dry run mode** - Test your configuration without taking any action
- **Drop-in configuration** - Modular config files in `/etc/scanban.d/`
- **Works great with ipset** - Efficient IP blocking for high-volume scenarios

## Quickstart

### Test Against a Log File

Before running scanban as a daemon, test your configuration against existing logs:

```bash
# Dry run against a specific log file
scanban -n -f /var/log/auth.log -c /etc/scanban.toml

# Scan entire file (not just new lines) with verbose output
scanban -n -a -v -f /var/log/auth.log

# Test from stdin
cat /var/log/auth.log | scanban -n -f -
```

The dry run mode (`-n`) shows what would be banned without actually executing any actions.

### Setup as Systemd Daemon (Debian Package)

If you installed scanban from the Debian package:

1. **Configure scanban** - Edit `/etc/scanban.toml` to define your rules and actions (see Configuration section below)

2. **Set secure permissions** - The config file contains shell commands that will be executed so ensure only root has access:
   ```bash
   sudo chmod 600 /etc/scanban.toml
   sudo chown root:root /etc/scanban.toml
   ```

3. **Enable and start the service**:
   ```bash
   sudo systemctl enable scanban
   sudo systemctl start scanban
   ```

4. **Check the status**:
   ```bash
   sudo systemctl status scanban
   ```

5. **View logs**:
   ```bash
   sudo journalctl -u scanban -f
   ```

In daemon mode, scanban continuously tails the configured log files and takes action in real-time as malicious activity is detected.

## Command Line Options

```
$ scanban -h
Usage of scanban:
  -a    scan the entirety of the file, not just new lines
  -c string
        config file (default "/etc/scanban.toml")
  -d string
        drop-in directory (default "/etc/scanban.d")
  -f string
        specific file to scan
  -n    dry run (show what would happen without taking action)
  -t    test complete merged config
  -u string
        unbanlist file (default "/var/lib/scanban/unbanlist.toml")
  -v    verbose output
  -x    dump complete merged config
```

**Common usage patterns:**

- **Daemon mode**: `scanban` (uses config file to tail configured logs)
- **Test configuration**: `scanban -n -a -v` (dry run against all configured files)
- **Scan specific file**: `scanban -n -f /var/log/auth.log`
- **Scan from stdin**: `cat /var/log/auth.log | scanban -n -f -`
- **Debug config**: `scanban -x` (dump merged configuration)

## Configuration

For more configuration examples and deployment strategies, see the [github wiki](https://github.com/penguinpowernz/scanban/wiki).

The main configuration file is located at `/etc/scanban.toml`. Additional configuration files can be placed in `/etc/scanban.d/` (must have `.toml` extension) for better organization - these will be automatically merged with the main config.

**Security Note:** Since config files contain shell commands that will be executed as root, keep strict permissions: `chmod 600` and `chown root:root` are recommended.

**Important:** TOML format requires escaping in regular expressions:
- **Double-quoted strings**: Use double backslashes: `"\\d+"` instead of `"\d+"`
- **Single-quoted strings**: Use single backslashes: `'\d+'` (no escaping needed for backslashes)

**Unbanning:** Automatic unbanning is essential to prevent memory exhaustion and iptables bloat. Attackers typically don't reuse the same IP for extended periods, so temporary bans (hours to days) are sufficient and more performant than permanent bans.

### Configuration Reference

| Key | Description | Example |
|---|---|---|
| `files` | List of log files or Docker containers to monitor | `files = ["/var/log/auth.log", "docker://nginx"]` |
| `whitelist` | IP addresses or CIDR ranges to never ban | `whitelist = ["127.0.0.1", "192.168.1.0/24"]` |
| `bantime` | Duration to ban IPs (in hours) | `bantime = 24` |
| `threshold` | Number of offenses required before banning | `threshold = 3` |
| `ip_regex` | Default regex pattern to extract IP addresses from log lines | `ip_regex = "(\\d+\\.\\d+\\.\\d+\\.\\d+)"` |
| `action` | Default action name to execute when banning | `action = "ipsetblock"` |
| `unban_action` | Default action name to execute when unbanning | `unban_action = "ipsetunblock"` |
| `dry_run` | Enable dry run mode (no actions executed) | `dry_run = true` |
| `verbose` | Enable verbose logging | `verbose = true` |
| `do_bans` | Enable/disable ban execution | `do_bans = true` |
| `do_unbans` | Enable/disable automatic unbanning | `do_unbans = true` |
| `unban_list` | Path to store scheduled unbans | `unban_list = "/var/lib/scanban/unbanlist.toml"` |
| `include` | Drop-in directory for additional configs | `include = "/etc/scanban.d"` |

### Global Settings

Global settings are defined at the top level of the config file and apply to all rules by default. Individual rules can override these settings.

```toml
# Operational settings
dry_run = false
verbose = false
do_bans = true
do_unbans = true

# Default ban parameters
bantime = 24        # Ban for 24 hours
threshold = 3       # Require 3 offenses before banning
ip_regex = "(\\d+\\.\\d+\\.\\d+\\.\\d+)"
action = "ipsetblock"
unban_action = "ipsetunblock"
```

### Files

Specify which log sources to monitor. scanban supports both regular files and Docker container logs.

```toml
files = [
  "/var/log/auth.log",
  "/var/log/ufw.log",
  "docker://nginx",        # Monitor Docker container logs
  "docker://mysql"
]
```

Each line from these sources is tested against all configured rules. When a line matches a rule's pattern and an IP is extracted, the threshold counter for that IP is incremented.

### Whitelist

Prevent specific IPs or entire networks from ever being banned, even if they match rules. Supports both individual IPs and CIDR notation.

```toml
whitelist = [
  "127.0.0.1",           # Localhost
  "192.168.1.0/24",      # Local network
  "10.0.0.0/8"           # Private network
]
```

### Actions

Actions define named shell commands to execute when banning or unbanning an IP. These can be iptables/ipset commands, custom scripts, or any shell command.

```toml
[actions]
# iptables-based blocking (not recommended)
blockit = "iptables -A INPUT -s $ip -j DROP && iptables -A OUTPUT -d $ip -j DROP"
unblockit = "iptables -D INPUT -s $ip -j DROP && iptables -D OUTPUT -d $ip -j DROP"

# ipset-based blocking (more efficient for many IPs)
ipsetblock = "ipset add scanban $ip"
ipsetunblock = "ipset del scanban $ip"

# Custom notification
notify = "/usr/local/bin/alert-slack.sh"
```

**Variable Substitution:** Use `$ip` in commands, which will be replaced with the actual IP address. Commands are executed via `bash -c`.

**Environment Variables:** All actions have access to these environment variables:

| Variable | Description |
| --- | --- |
| `SB_IP` | The offending IP address |
| `SB_BANTIME` | Ban duration in hours |
| `SB_FILENAME` | Log file or container where IP was detected |
| `SB_LINE` | Complete log line that triggered the ban |
| `SB_NAME` | Name of the action being executed |
| `SB_UNBANACTION` | Name of the corresponding unban action |

### Rules

Rules define what patterns to match in log lines and how to handle them. Each rule is defined with `[[rules]]` and can match one or more patterns. When a pattern matches, scanban extracts the IP address and tracks violations.

**Rule Parameters:**

| Key | Required | Description | Example |
|---|---|---|---|
| `pattern` | Yes* | Single regex pattern to match | `pattern = "Authentication failed"` |
| `patterns` | Yes* | Multiple regex patterns (any can match) | `patterns = ["Invalid user", "Failed password"]` |
| `ip_regex` | No | Custom regex to extract IP (uses global default if omitted) | `ip_regex = "SRC=(\\d+\\.\\d+\\.\\d+\\.\\d+)"` |
| `action` | No | Override global ban action | `action = "blockit"` |
| `unban_action` | No | Override global unban action | `unban_action = "unblockit"` |
| `bantime` | No | Override global ban duration (hours) | `bantime = 48` |
| `threshold` | No | Override global offense threshold | `threshold = 1` |

*Either `pattern` or `patterns` is required.

**Examples:**

Simple single-pattern rule:
```toml
[[rules]]
pattern = "Authentication failed"
```

Catch multiple SSH brute force patterns:
```toml
[[rules]]
patterns = [
  "sshd.*Invalid user \\w+ from",
  "sshd.*User \\w+ from .* not allowed because not listed in AllowUsers",
  "sshd.*Did not receive identification string from"
]
threshold = 1    # Ban after just one offense
```

Custom IP extraction for firewall logs (when multiple IPs are in the line):
```toml
[[rules]]
pattern = "IN=\\w+ .*DPT=138"
ip_regex = " SRC=(\\d+\\.\\d+\\.\\d+\\.\\d+) "  # Extract source IP specifically
```

## Example Output

When running in dry run mode, scanban shows what actions would be taken:

```
$ scanban -n -f ./auth2.log -c ./scanban.toml
2025/06/22 21:45:54 loading config
2025/06/22 21:45:54 opening unban list
2025/06/22 21:45:54 selecting scanner strategy
2025/06/22 21:45:54 building line handlers
2025/06/22 21:45:54 built 1 rules
2025/06/22 21:45:54 built 5 actions
2025/06/22 21:45:54 starting scanner loop
2025/06/22 21:45:54 actioned=true filename=./auth2.log ip=216.144.248.30 action=ipsetblock release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log ip=80.94.95.15 action=ipsetblock release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log ip=115.247.46.121 action=ipsetblock release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log ip=216.144.248.25 action=ipsetblock release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log ip=69.162.124.227 action=ipsetblock release=2025-06-23T21:45
2025/06/22 21:45:54 10 lines scanned in 0.00 seconds
2025/06/22 21:45:54 9 actioned, 1 rejected
2025/06/22 21:45:54 shutting down
```

Each ban action shows:
- **actioned**: Whether the action was taken
- **filename**: Source log file or container
- **ip**: Banned IP address
- **action**: Action executed
- **release**: When the IP will be unbanned

## Complete Example Configuration

```toml
# /etc/scanban.toml

# Global settings
do_bans = true
do_unbans = true
bantime = 24
threshold = 3
ip_regex = "(\\d+\\.\\d+\\.\\d+\\.\\d+)"
action = "ipsetblock"
unban_action = "ipsetunblock"

# Log sources
files = [
  "/var/log/auth.log",
  "/var/log/ufw.log",
  "docker://nginx"
]

# Never ban these
whitelist = [
  "127.0.0.1",
  "192.168.1.0/24"
]

# Define actions
[actions]
ipsetblock = "ipset add scanban $ip"
ipsetunblock = "ipset del scanban $ip"

# SSH brute force detection
[[rules]]
patterns = [
  "sshd.*Invalid user \\w+ from",
  "sshd.*User \\w+ from .* not allowed because not listed in AllowUsers",
  "sshd.*Did not receive identification string from"
]
ip_regex = "from (\\d+\\.\\d+\\.\\d+\\.\\d+)"
threshold = 1

# Exploit scanner detection (phpMyAdmin, WordPress)
[[rules]]
patterns = [
  "wp-admin",
  "phpMyAdmin"
]
```

## Why scanban instead of fail2ban?

Scanban was created as a modern alternative to fail2ban with these goals:

- **Simpler configuration** - fail2ban's configuration can be verbose and complex
- **Single binary** - Easy deployment with no Python dependencies
- **Performance** - Go's efficiency handles high-volume logs well
- **Docker integration** - Native support for monitoring Docker container logs
- **Modern codebase** - Easier to modify and extend

## Contributing

Issues and pull requests welcome at https://github.com/penguinpowernz/scanban

## Future Roadmap

- [ ] IPv6 support
- [ ] TCP/Unix socket for external ban tools (BYO firewall integration)
- [ ] No-op action for monitoring without banning
- [ ] More comprehensive test coverage
- [x] add a drop in for protecting a ruby on rails app
- [x] add a drop in for blocking IPs based on tripwires
- [x] add a drop in for blocking IPs based on bad SSH login attempts
- [ ] properly handle reverse DNS/PTR records based IPs
