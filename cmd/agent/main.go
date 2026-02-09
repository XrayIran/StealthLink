package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"stealthlink/internal/agent"
	"stealthlink/internal/config"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	reloader, err := config.NewReloadable(*configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}
	defer reloader.Close()
	cfg := reloader.Get()
	if cfg.Role != "agent" {
		log.Fatalf("config role must be agent")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleSignals(cancel)

	restartCh := make(chan *config.Config, 1)
	reloader.Watch(func(old, next *config.Config) {
		if next.Role != "agent" {
			log.Printf("ignoring config reload with non-agent role: %s", next.Role)
			return
		}
		select {
		case restartCh <- next:
		default:
		}
	})

	runCtx, runCancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go runAgent(runCtx, cfg, errCh)

	for {
		select {
		case <-ctx.Done():
			runCancel()
			<-errCh
			return
		case next := <-restartCh:
			log.Printf("config reloaded: restarting agent with updated settings")
			runCancel()
			<-errCh
			runCtx, runCancel = context.WithCancel(ctx)
			errCh = make(chan error, 1)
			go runAgent(runCtx, next, errCh)
		case err := <-errCh:
			if ctx.Err() != nil {
				return
			}
			log.Printf("agent failed: %v", err)
			runCtx, runCancel = context.WithCancel(ctx)
			errCh = make(chan error, 1)
			go runAgent(runCtx, reloader.Get(), errCh)
		}
	}
}

func handleSignals(cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}

func runAgent(ctx context.Context, cfg *config.Config, errCh chan<- error) {
	ag := agent.New(cfg)
	errCh <- ag.Start(ctx)
}
