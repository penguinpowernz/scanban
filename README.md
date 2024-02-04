# scanban

A simple alternative to fail2ban that watches system logs and takes action on IPs.

**This is beta software you should probably validate yourself it before running in production**

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
  -n    dry run
```

Using `scanban -n -a` is a handy way to see what would happen based on what is in the current files.

When installed from the Debian package it can be manipulated as a systemd service:

    systemctl enable scanban
    systemctl start scanban

## Configuration

The configuration file can be found at `/etc/scanban.toml` and extra configs can be dropped
into `/etc/scanban.d` to keep things tidy (must have the extension `.toml`). As these config
files define commands to run, it is important to keep strict permissons, 0600 recommended.

The config file is broken up like so:

A whitelist, these IPs will never be banned as well as how long IPs should be banned for:
```toml
whitelist = [
  "127.0.0.1",
  "192.168.1.0/24"
]

bantime = 24 # in hours, can be overwritten for files and rules
```

The actions to take on an abusive IP.  The variables $ip and $desc will be replaced with the offending IP and the rule description. Note
that these actions will be passed through bash like `bash -c "iptables -A INPUT -s 182.23.31.12 -j DROP"`. When this command is run it also has access to the following envvars:

- SB_IP
- SB_DESC
- SB_BANTIME
- SB_FILENAME
- SB_LINE
- SB_NAME
- SB_UNBANACTION


```toml
[actions]
blockit = "iptables -A INPUT -s $ip -j DROP"
notify = "pingslack"
unblockit = "iptables -D INPUT -s $ip -j DROP"
```

A file to scan including the action to take, and the regex to find the IP by.  This can be repeated for as many files as you need to scan.
```toml
[[files]]
path = "/var/log/nginx/access.log"
action = "blockit"                      # this is used for all rules, unless overriden
ip_regex = " (\\d+.\\d+.\\d+.\\d+) "    # this is used for all rules, unless overriden
unban_action = "unblockit"              # this is used for all rules, unless overriden
bantime = 1                             # this overrides the 24 hours specified in the config
rules = [
  { pattern = "phpMyAdmin", desc = "attempt to access invalid URL" },
  { pattern = "wp-admin", desc = "attempt to access invalid URL", action = "notify", unban_action = "" }
]
```

The rules consist of the following fields:

```toml
rules = [{
  pattern      = "40[4,0,3,1]",          # the pattern to scan for, can be a regex
  threshold    = 10                      # how many times the pattern should be seen before taking action
  desc         = "sus 400 errors"        # a description of the rule
  ip_regex     = "(\\d+.\\d+.\\d+.\\d+)" # override the regex that finds the IP address
  action       = "notify"                # override the action that should be called for this rule
  unban_action = "unblockit"             # override the unban action that should be called for this rule
  bantime      = 1                       # override the bantime that should be used for this rule
}]
```
