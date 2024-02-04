package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
)

var (
	cfgFile   string
	dryRun    bool
	scanAll   bool
	dropInDir string
	unbanlist string
)

func main() {
	flag.StringVar(&cfgFile, "c", "/etc/scanban.toml", "config file")
	flag.StringVar(&dropInDir, "d", "/etc/scanban.d", "drop-in directory")
	flag.BoolVar(&dryRun, "n", false, "dry run")
	flag.BoolVar(&scanAll, "a", false, "scan the entirety of the file, not just new lines")
	flag.StringVar(&unbanlist, "u", "/var/lib/scanban/unbanlist.toml", "unbanlist file")
	flag.Parse()

	cfg, err := NewConfig(cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	// merge in any config files from the drop-in directory
	if dropInDir != "" {
		filepath.WalkDir(dropInDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if err := cfg.MergeFile(path); err != nil {
				log.Println("failed to merge", path, err)
				return nil
			}
			log.Println("merged", path)
			return nil
		})
	}

	// open the unban list
	list, err := NewUnbanList(unbanlist)
	if err != nil {
		log.Fatal(err)
	}

	// start the unban loop
	go unbanLoop(list)

	// make the channel through which any rule violations will be received
	actionChan := make(chan Action)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// compile all the rules and start scanning the files
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
		case actn := <-actionChan:
			seq++

			log.Printf("%d: %s line matches rule for IP %s", seq, actn.Filename, actn.IP)
			log.Printf("%d: %s", seq, actn.Line)

			cmdstring, found := actn.CmdString(cfg.Actions)
			if !found {
				log.Printf("%d SKIP unknown action: %s", seq, actn.Name)
				continue
			}

			if err := actn.Valid(cfg); err != nil {
				log.Printf("%d SKIP %s", seq, err)
				continue
			}

			log.Printf("%d: taking action %s: %s", seq, actn.Name, cmdstring)

			if dryRun {
				log.Printf("%d: SKIP dry run", seq)
				continue
			}

			cmd := actn.Cmd(cmdstring)
			if err := cmd.Run(); err != nil {
				log.Printf("%d: failed to take action %s on %s: %s", seq, actn.Name, actn.IP, err)
				continue
			}

			list.AddEntry(actn)
		}
	}
}

type tailer interface {
	Tail(ctx context.Context, lines chan string)
}

func scanFile(ctx context.Context, actionChan chan Action, fcfg *FileConfig) {
	lines := make(chan string)

	var t tailer
	var err error

	switch {
	case fcfg.Path != "":
		t, err = NewTailer(fcfg.Path, !scanAll)
		if err != nil {
			log.Printf("failed to open %s: %s", fcfg.Path, err)
			return
		}
	case fcfg.Docker != "":
		t, err = NewDockerTailer(fcfg.Docker, !scanAll)
		if err != nil {
			log.Printf("failed to open %s: %s", fcfg.Docker, err)
			return
		}
	default:
		log.Printf("failed to open tail: no path or docker specified in config")
		return
	}

	go t.Tail(ctx, lines)

	checkLine := makeLineChecker(actionChan, fcfg.Path, fcfg.Rules)

	for {
		select {
		case <-ctx.Done():
			return
		case line := <-lines:
			checkLine(line)
		}
	}
}
