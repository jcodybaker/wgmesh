package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var debug bool
var ctx context.Context
var ll log.FieldLogger

var rootCmd = &cobra.Command{
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if debug {
			log.SetLevel(log.DebugLevel)
		}
		if isatty.IsTerminal(os.Stdout.Fd()) {
			log.SetFormatter(&log.TextFormatter{})
		}
	},
}

func init() {
	viper.SetEnvPrefix("wgmesh")

	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)

	ctx = signalContext(context.Background())
	ll = log.WithContext(ctx)
}

func main() {
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug logging")
	rootCmd.Execute()
}

func signalContext(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // exit hard for the impatient
	}()

	return ctx
}
