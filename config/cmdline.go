package config

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

var (
	commandLine    = pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
	DisplayVersion = commandLine.BoolP("version", "v", false, "print version and exit")
	DisplayHelp    = commandLine.BoolP("help", "h", false, "print help and exit")
	File           = commandLine.StringP("config", "c", "config.yaml", "configuration file")
)

func CmdLine() {
	if err := commandLine.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *DisplayVersion {
		fmt.Println(Version)
		os.Exit(0)
	}
	if *DisplayHelp {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		commandLine.PrintDefaults()
		os.Exit(0)
	}
}
