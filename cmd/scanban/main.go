package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	cfgFile   string
	dryRun    bool
	scanAll   bool
	dropInDir string
)

func main() {
	flag.StringVar(&cfgFile, "c", "", "config file")
	flag.StringVar(&dropInDir, "d", "", "drop-in directory (e.g. /etc/succeed2ban.d)")
	flag.BoolVar(&dryRun, "n", false, "dry run")
	flag.BoolVar(&scanAll, "a", false, "scan all of the existing files")
	flag.Parse()

	cfg, err := NewConfig(cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	if dropInDir != "" {
		filepath.WalkDir(dropInDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			cfg.MergeFile(path)
			return nil
		})
	}

	actionChan := make(chan Action)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, fcfg := range cfg.Files {
		for _, rule := range fcfg.Rules {
			rule.Compile(fcfg)
		}

		go scanFile(ctx, actionChan, fcfg)
	}

	var seq int
	for {
		select {
		case <-ctx.Done():
			return
		case action := <-actionChan:
			seq++

			if cfg.IsWhitelisted(action.IP) {
				log.Printf("%d SKIP whitelisted ip: %s", seq, action.IP)
				continue
			}

			cmdtmpl, found := cfg.Actions[action.Name]
			if !found {
				log.Printf("%d SKIP unknown action: %s", seq, action.Name)
				continue
			}

			cmdstring := strings.ReplaceAll(cmdtmpl, "$ip", action.IP)
			cmdstring = strings.ReplaceAll(cmdstring, "$msg", action.Line)

			if dryRun {
				log.Printf("%d DRY RUN command for match in %s", seq, action.Filename)
				log.Printf("%d DRY RUN trigger: %s", seq, action.Line)
				log.Printf("%d DRY RUN: %s", seq, cmdstring)
				continue
			}

			bits := strings.Split(cmdstring, " ")
			cmd := exec.Command(bits[0], bits[1:]...)
			cmd.Run()
		}
	}
}

type Action struct {
	Name     string
	IP       string
	Line     string
	Filename string
}

func scanFile(ctx context.Context, actionChan chan Action, fcfg *FileConfig) {
	lines := make(chan string)
	t, err := NewTailer(fcfg.Path, !scanAll)
	if err != nil {
		log.Printf("failed to open %s: %s", fcfg.Path, err)
		return
	}

	go t.Tail(ctx, lines)

	for {
		select {
		case <-ctx.Done():
			return
		case line := <-lines:
			checkLine(actionChan, line, fcfg.Rules)
		}
	}
}

func checkLine(actionChan chan Action, line string, rules []*RuleConfig) {
	for _, rule := range rules {
		if !rule.Match(line) {
			continue
		}

		var ip string
		if ip = rule.FindIP(line); ip == "" {
			log.Printf("WARN: line matched but failed to detect IP: %s", line)
			continue
		}

		if rule.Threshold > 0 {
			rule.hits[ip]++
			if rule.hits[ip] < rule.Threshold {
				continue
			}
		}

		actionChan <- Action{
			Name: rule.Action,
			IP:   ip,
			Line: line,
		}
	}
}
