# scanban

A simple alternative to fail2ban that watches system logs and takes action on IPs.

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

## Configuration

The configuration file can be found at `/etc/scanban.toml` and extra configs can be dropped
into `/etc/scanban.d` to keep things tidy (must have the extension `.toml`). As these config
files define commands to run, it is important to keep strict permissons, 0600 recommended.

The config file is broken up like so:

A whitelist, these IPs will never be banned:
```toml
whitelist = [
  "127.0.0.1",
  "192.168.1.0/24"
]
```

The actions to take on an abusive IP.  The variables $ip and $desc will be replaced with the offending IP and the rule description. Note
that these actions will be passed through bash like `bash -c "iptables -A INPUT -s 182.23.31.12 -j DROP"`.
```toml
[actions]
blockit = "iptables -A INPUT -s $ip -j DROP"
notify = "pingslack '$desc from $ip'"
```

A file to scan including the action to take, and the regex to find the IP by.  This can be repeated for as many files as you need to scan.
```toml
[[files]]
path = "/var/log/nginx/access.log"
action = "blockit"                  # this is used for all rules, unless overriden
ip_regex = " (\d+.\d+.\d+.\d+) "    # this is used for all rules, unless overriden
rules = [
  { pattern = "phpMyAdmin", desc = "attempt to access invalid URL" }
  { pattern = "wp-admin", desc = "attempt to access invalid URL", action = "notify" }
]
```

The rules consist of the following fields:

```toml
{
  pattern   = "40[4,0,3,1]",     # the pattern to scan for, can be a regex
  threshold = 10                 # how many times the pattern should be seen before taking action
  desc      = "sus 400 errors"   # a description of the rule
  ip_regex  = "(\d+)"            # override the regex that finds the IP address
  action    = "notify"           # override the action that should be called for this rule
}
```
