package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/penguinpowernz/scanban/pkg/actions"
	"github.com/penguinpowernz/scanban/pkg/config"
	"github.com/penguinpowernz/scanban/pkg/logit"
	"github.com/penguinpowernz/scanban/pkg/metrics"
	"github.com/penguinpowernz/scanban/pkg/once"
	"github.com/penguinpowernz/scanban/pkg/rules"
	"github.com/penguinpowernz/scanban/pkg/scan"
	"github.com/penguinpowernz/scanban/pkg/threshold"
	"github.com/penguinpowernz/scanban/pkg/unban"
	"github.com/penguinpowernz/scanban/pkg/whitelist"
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
	stateFile string
)

func main() {
	flag.StringVar(&cfgFile, "c", "/etc/scanban.toml", "config file")
	flag.StringVar(&dropInDir, "d", "/etc/scanban.d", "drop-in directory")
	flag.BoolVar(&dryRun, "n", false, "dry run")
	flag.StringVar(&filename, "f", "", "entire file to scan")
	flag.BoolVar(&scanAll, "a", false, "scan the entirety of the file, not just new lines")
	flag.StringVar(&unbanlist, "u", "", "unbanlist file")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.BoolVar(&dumpCfg, "x", false, "dump complete merged config")
	flag.BoolVar(&testCfg, "t", false, "test complete merged config")
	flag.StringVar(&stateFile, "s", "/var/run/scanban.state", "state file path for metrics")
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

	if testCfg {
		return
	}

	if dumpCfg {
		cfg.Encode(os.Stdout)
		return
	}

	// open the unban list
	log.Println("opening unban list")
	ublist, err := unban.NewList(cfg.UnbanList, cfg.DoUnbans)
	if err != nil {
		log.Fatal(err)
	}

	if !dryRun && cfg.DoUnbans {
		log.Println("starting unban loop")
		go unban.Loop(ctx, ublist)
	}

	log.Println("selecting scanner strategy")

	// engineFor builds a per-file rule engine from a FileConfig's compiled rules.
	engineFor := func(fc *config.FileConfig) scan.Handler {
		ruls := rules.BuildRules(fc.CompiledRules)
		log.Printf("built %d rules for %s", len(ruls), fc.Path)
		return rules.NewEngine(ruls)
	}

	// globalEngine collects all rules across all files for use with -f / stdin.
	globalEngine := func() scan.Handler {
		var allRules []*config.RuleConfig
		for _, fc := range cfg.Files {
			allRules = append(allRules, fc.CompiledRules...)
		}
		ruls := rules.BuildRules(allRules)
		log.Printf("built %d rules (global)", len(ruls))
		return rules.NewEngine(ruls)
	}()

	var scanners scan.Scanners
	switch {
	case filename == "-":
		scanners = scan.FromStdin(dryRun, globalEngine)
	case filename != "":
		scanners = scan.FromFile(filename, dryRun, globalEngine)
	default:
		scanners = scan.BuildScanners(cfg.Files, dryRun, engineFor)
	}

	log.Println("building line handlers")
	wl := whitelist.New(cfg.Whitelist)
	thresholds := threshold.New()
	actor := actions.BuildActions(cfg.Actions, cfg.DoBans)
	log.Println("built", len(cfg.Actions), "actions")
	logger := logit.New()
	elogger := logit.Errors(verbose)

	log.Println("starting scanner loop")

	// Start metrics writer goroutine
	go metrics.StartWriter(ctx, stateFile, 5*time.Second)

	for line := range scanners.Scan(ctx) {
		once.Handle(line)        // ensure each line is processed only once
		line.Engine.Handle(line) // run the per-file rule engine
		wl.Handle(line)          // ignore whitelisted IPs
		thresholds.Handle(line)  // check offense threshold
		actor.Handle(line)       // execute ban actions
		ublist.Handle(line)      // schedule unban
		logger.Handle(line)      // log the action taken
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

// overwriteConfigWithFlags overwrites the loaded config file with CLI flags
func overwriteConfigWithFlags(cfg *config.Config) {
	if cfg.Include != "" && dropInDir == "" {
		dropInDir = cfg.Include
	}

	if unbanlist != "" {
		cfg.UnbanList = unbanlist
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
