package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/ratsd/config"
)

func TestCommandLine(test *testing.T) {
	for _, testCase := range []struct {
		name     string
		args     []string
		expected string
		wantErr  bool
	}{
		{name: "help", args: []string{"--help"}, expected: "configuration file"},
		{name: "short help", args: []string{"-h"}, expected: "configuration file"},
		{name: "version", args: []string{"--version"}, expected: "test-version\n"},
		{name: "short version", args: []string{"-v"}, expected: "test-version\n"},
		{name: "default config", expected: "open config.yaml", wantErr: true},
		{name: "config", args: []string{"--config", "missing.yaml"}, expected: "open missing.yaml", wantErr: true},
		{name: "short config", args: []string{"-c", "missing.yaml"}, expected: "open missing.yaml", wantErr: true},
		{name: "unknown flag", args: []string{"--unknown"}, expected: "unknown flag", wantErr: true},
	} {
		test.Run(testCase.name, func(test *testing.T) {
			args := append([]string{"-test.run=^TestCommandLineProcess$", "--"}, testCase.args...)
			command := exec.Command(os.Args[0], args...)
			command.Dir = test.TempDir()
			command.Env = append(os.Environ(), "RATSD_CONFIG_TEST_PROCESS=1")
			output, err := command.CombinedOutput()
			if testCase.wantErr {
				require.Error(test, err, string(output))
			} else {
				require.NoError(test, err, string(output))
			}
			assert.Contains(test, string(output), testCase.expected)
		})
	}
}

func TestCommandLineProcess(test *testing.T) {
	if os.Getenv("RATSD_CONFIG_TEST_PROCESS") != "1" {
		return
	}
	for index, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"ratsd"}, os.Args[index+1:]...)
			config.Version = "test-version"
			main()
			os.Exit(0)
		}
	}
	test.Fatal("missing command-line separator")
}
