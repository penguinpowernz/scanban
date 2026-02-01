package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/penguinpower/scanban/pkg/actions"
	"github.com/penguinpower/scanban/pkg/config"
	"github.com/penguinpower/scanban/pkg/logit"
	"github.com/penguinpower/scanban/pkg/metrics"
	"github.com/penguinpower/scanban/pkg/once"
	"github.com/penguinpower/scanban/pkg/rules"
	"github.com/penguinpower/scanban/pkg/scan"
	"github.com/penguinpower/scanban/pkg/threshold"
	"github.com/penguinpower/scanban/pkg/unban"
	"github.com/penguinpower/scanban/pkg/whitelist"
)

var (
	cfgFile   string
	dryRun    bool
	scanAll   bool
	dropInDir string
	unbanlist string
	verbose   bool
	dumpCfg   bool
	testCfg   bool
	filename  string
)

func main() {
	flag.StringVar(&cfgFile, "c", "/etc/scanban.toml", "config file")
	flag.StringVar(&dropInDir, "d", "/etc/scanban.d", "drop-in directory")
	flag.BoolVar(&dryRun, "n", false, "dry run")
	flag.StringVar(&filename, "f", "", "entire file to scan")
	flag.BoolVar(&scanAll, "a", false, "scan the entirety of the file, not just new lines")
	flag.StringVar(&unbanlist, "u", "/var/lib/scanban/unbanlist.toml", "unbanlist file")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.BoolVar(&dumpCfg, "x", false, "dump complete merged config")
	flag.BoolVar(&testCfg, "t", false, "test complete merged config")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("loading config")
	cfg, err := config.LoadFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	overwriteConfigWithFlags(cfg)
	cfg.MergeDropin(dropInDir)

	// if err := cfg.Validate(); err != nil {
	// 	log.Fatal(err)
	// }

	if testCfg {
		return
	}

	if dumpCfg {
		cfg.Encode(os.Stdout)
		return
	}

	// open the unban list
	log.Println("opening unban list")
	ublist, err := unban.NewList(unbanlist)
	if err != nil {
		log.Fatal(err)
	}

	if !dryRun {
	// start the unban loop
		log.Println("starting unban loop")
		go unban.Loop(ctx, ublist)
	}

	log.Println("selecting scanner strategy")
	var scanners scan.Scanners
	switch {
	case filename == "-":
		scanners = scan.FromStdin(dryRun)
	case filename != "":
		scanners = scan.FromFile(filename, dryRun)
	default:
		scanners = scan.BuildScanners(cfg.Files, dryRun)
	}

	log.Println("buliding line handlers")
	wl := whitelist.New(cfg.Whitelist)
	ruls := rules.BuildRules(cfg.Rules)
	log.Println("built", len(ruls), "rules")
	eng := rules.NewEngine(ruls)
	thresholds := threshold.New()
	actor := actions.BuildActions(cfg.Actions)
	log.Println("built", len(actor), "actions")
	logger := logit.New()
	elogger := logit.Errors(verbose)

	log.Println("starting scanner loop")

	// start all the scanners and listen for line contexts
	for line := range scanners.Scan(ctx) {
		// log.Println("got line", line.Line)
		// bailout.Handle(line)
		once.Handle(line)       // ensure to process each line only once
		eng.Handle(line)        // run the line through the rule engine
		wl.Handle(line)         // ignore the line if the IP is in the whitelist
		thresholds.Handle(line) // run the line through the threshold checker
		actor.Handle(line)      // run the actions for any lines that match
		ublist.Handle(line)     // add the unban actions
		logger.Handle(line)     // log the action taken (if any) for the line
		elogger.Handle(line)
		metrics.Handle(line)
		}

	metrics.Done()
	log.Printf("%d lines scanned in %0.2f seconds", metrics.Lines, metrics.Duration)
	log.Printf("%d actioned, %d rejected", metrics.Actioned, metrics.Errs)
	log.Println("shutting down")
	stop()
	<-ctx.Done()
}

// overwriteConfigWithFlags overwrites the loaded config file, with the CLI flags
func overwriteConfigWithFlags(cfg *config.Config) {
	if cfg.Include != "" && dropInDir == "" {
		dropInDir = cfg.Include
	}

	if dryRun {
		cfg.DryRun = true
	}

	if verbose {
		cfg.Verbose = true
	}

	if cfg.Verbose {
		verbose = true
	}

	if cfg.DryRun {
		dryRun = true
	}
}
