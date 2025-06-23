# scanban

A simple alternative to fail2ban.

System logs are scanned for certain patterns that indicate a malicious host is trying to scan the machine
for exploits.  If the IP of the malicious host can be found on the log line, we can use that to ban the
offender.

This allows us to ban bots that try to brute force SSH endpoints to search for vulnerable phpMyAdmin or
wordpress instances, and the like.

## Features

- easy configuration
- regular expression based matching
- tail new lines from log files and docker container logs
- ban IP addresses for a specific period of time
- execute custom actions when a ban is triggered
- execute custom actions when a ban is lifted
- log actions taken to un/ban
- test configuration against specific logs with dry run mode
- whitelist IP addresses
- drop-in directory support for modular configuration
- great to pair with `ipset`

## Usage

The command has the following args:

```
$ scanban -h
Usage of scanban:
  -a    scan the entirety of the file, not just new lines
  -c string
        config file (default "/etc/scanban.toml")
  -d string
        drop-in directory (default "/etc/scanban.d")
  -f string
        entire file to scan
  -n    dry run
  -u string
        unbanlist file (default "/var/lib/scanban/unbanlist.toml")
  -v    verbose
```

Using `scanban -n -a` is a handy way to see what would happen based on what is in the current files, or feed
it directly using `scanban -n -f /var/log/auth.log` or `cat /var/log/auth.log | scanban -n -f -`.

The normal mode of operation is to tail new lines from log files and docker containers as a daemon.

When installed from the Debian package it can be manipulated as a systemd service:

    systemctl enable scanban
    systemctl start scanban

Please see the [github wiki](https://github.com/penguinpowernz/scanban/wiki) for configuration examples and broader strategies.

## Configuration

The configuration file can be found at `/etc/scanban.toml` and extra configs can be dropped
into `/etc/scanban.d` to keep things tidy (must have the extension `.toml`). As these config
files define commands to run, **it is important to keep strict permissons, 0600 recommended**.

Unfortunately the TOML format requires double escapes in the regular expression definitions.

**Unbanning** is required so that you don't fill up memory and IP tables with banned IPs which can
hamper performance - also the bot machines don't use the same host for long.

### Global

A number of variables can be defined at the top level of the config file so that you don't need to
set them for every single rule.  Each rule can override these in it's own definition.

```toml
bantime = 1
threshold = 3
ip_regex = "(\\d+\\.\\d+\\.\\d+\\.\\d+)"
action = "blockit"
unban_action = "unblockit"
```

We can see the default actions to take.  We can also see the default threshold for how many times
an IP should be seen offending before being banned.  The default bantime is set to 1 hour.

### Files

This is a list of files to scan and feed to the rules engine.

```toml
files = [
  "/var/log/auth.log",
  "/var/log/ufw.log",
]
```

The lines will be delivered to all rules to attempt matching and then banning.

### Whitelist

This allows you to ensure certain IPs or networks are never banned.

```toml
whitelist = [
  "127.0.0.1",
  "192.168.1.0/24"
]
```

### Actions

Actions define a shorthand reference name to use for system commands that will run to ban or unban an IP.  It can 
be an something like an iptables command or a path your own script.

```toml
[actions]
blockit = "iptables -A INPUT -s $ip -j DROP"
notify = "pingslack"
unblockit = "iptables -D INPUT -s $ip -j DROP"
ipsetblock = "ipset add scanban $ip"
ipsetunblock = "ipset del scanban $ip"
```

The variables in the command like `$ip` will be replaced with the offending IP. The commands will be passed through
bash like `bash -c "iptables -A INPUT -s 182.23.31.12 -j DROP"`. 

Every command is given environment variables when it is run, so for instance the action `pingslack` has access to
the following envvars:

| Envvar | Description |
| --- | --- |
| SB_IP | The actual offending IP |
| SB_BANTIME | The length of time to ban for (in hours) |
| SB_FILENAME | The file that the IP was seen in |
| SB_LINE | The full line that triggered the ban |
| SB_NAME | The name of the action (e.g. `notify`) |
| SB_UNBANACTION | The name of the action to take to unban |

### Rules

The rules are setup with the array style toml section that uses the double brackets and is based around a pattern or
set of patterns.  These patterns are used to match against the scanned logged lines.  Any that don't match will be
ignored while ones that match will be further processed.

```toml
[[rules]]
pattern = "Authentication failed"
```

You can also use a list of patterns to match against.  So this rule can catch any brute force attempts in auth.log:

```toml
[[rules]]
patterns = [
  "sshd.*Invalid user \\w+ from",
  "sshd.*User \\w+ from .* not allowed because not listed in AllowUsers",
  "sshd.*Did not receive identification string from"
]
```

The top level IP regex pattern is mostly suffice, but if there are more than one IP in the line you can specify a
regex just for the rule. This rule can detect machines scanning port 138 (eg. potential EternalBlue worm) and block
them completely on all ports:

```toml
[[rules]]
pattern = "IN=\\w+ .*DPT=138"
ip_regex = " SRC=(\\d+\\.\\d+\\.\\d+\\.\\d+) "
```

## Output

The output actions are shown in the logs:

```
$ scanban -n -f ./auth2.log -c ./scanban.toml -u ./unban.toml
2025/06/22 21:45:54 loading config
2025/06/22 21:45:54 opening unban list
2025/06/22 21:45:54 selecting scanner strategy
2025/06/22 21:45:54 buliding line handlers
2025/06/22 21:45:54 built 1 rules
2025/06/22 21:45:54 built 5 actions
2025/06/22 21:45:54 starting scanner loop
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=216.144.248.30       action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=80.94.95.15          action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=115.247.46.121       action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=216.144.248.25       action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=69.162.124.227       action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=37.198.207.35        action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=69.162.124.235       action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=216.144.248.28       action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 actioned=true filename=./auth2.log          ip=80.94.95.15          action=ipsetblock           release=2025-06-23T21:45
2025/06/22 21:45:54 10 lines scanned in 0.00 seconds
2025/06/22 21:45:54 9 actioned, 1 rejected
2025/06/22 21:45:54 shutting down
```

# TODO

- [ ] more tests
- [ ] serve rule triggers via TCP (BYO un/ban tool)
- [ ] serve rule triggers via UDS (BYO un/ban tool)
- [ ] IPv6 support
- [ ] add noop action for monitoring only

# Whats wrong with fail2ban?

To me fail2ban feels like legacy software these days. I wanted to make scanban because:

- I find the configuration format of fail2ban finnicky and overly verbose
- I like to avoid python software where possible
- I like single compiled binaries
- I am a golang fanboi
