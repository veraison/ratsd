// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/ratsd/api"
	mock_deps "github.com/veraison/ratsd/api/mocks"
	"github.com/veraison/ratsd/auth"
	"github.com/veraison/ratsd/config"
	"github.com/veraison/ratsd/log"
)

func TestPublicDiscovery(test *testing.T) {
	settings := viper.New()
	settings.Set("backend", "basic")
	settings.Set("users.foo.password", "$2b$12$yH/i2alYaIrVbKFkaYu5HOSf3JiZ0zPJlooufSRdO.6V3X/hXgTOq")
	authorizer, err := auth.NewAuthorizer(settings, log.Named("test"))
	require.NoError(test, err)
	test.Cleanup(func() { require.NoError(test, authorizer.Close()) })

	for _, testCase := range []struct {
		name          string
		method        string
		path          string
		authenticated bool
		wantStatus    int
		listAttesters bool
	}{
		{name: "public discovery", method: http.MethodGet, path: "/.well-known/veraison/ratsd", wantStatus: http.StatusOK, listAttesters: true},
		{name: "public discovery HEAD", method: http.MethodHead, path: "/.well-known/veraison/ratsd", wantStatus: http.StatusOK, listAttesters: true},
		{name: "protected evidence", method: http.MethodPost, path: "/ratsd/chares", wantStatus: http.StatusUnauthorized},
		{name: "protected attesters", method: http.MethodGet, path: "/ratsd/subattesters", wantStatus: http.StatusUnauthorized},
		{name: "protected nonce functions", method: http.MethodGet, path: "/ratsd/nonce-adjust-functions", wantStatus: http.StatusUnauthorized},
		{name: "authenticated evidence", method: http.MethodPost, path: "/ratsd/chares", authenticated: true, wantStatus: http.StatusBadRequest},
		{name: "authenticated attesters", method: http.MethodGet, path: "/ratsd/subattesters", authenticated: true, wantStatus: http.StatusOK, listAttesters: true},
		{name: "authenticated nonce functions", method: http.MethodGet, path: "/ratsd/nonce-adjust-functions", authenticated: true, wantStatus: http.StatusOK},
	} {
		test.Run(testCase.name, func(test *testing.T) {
			controller := gomock.NewController(test)
			manager := mock_deps.NewMockIManager(controller)
			if testCase.listAttesters {
				manager.EXPECT().GetPluginList().Return([]string{})
			}
			server := api.NewServer(log.Named("test"), manager, "all")
			request := httptest.NewRequest(testCase.method, testCase.path, nil)
			if testCase.authenticated {
				request.SetBasicAuth("foo", "Pa55w0rd$")
			}
			response := httptest.NewRecorder()
			newRouter(server, authorizer).ServeHTTP(response, request)
			assert.Equal(test, testCase.wantStatus, response.Code)
			if testCase.wantStatus == http.StatusUnauthorized {
				assert.NotEmpty(test, response.Header().Get("WWW-Authenticate"))
			} else {
				assert.Empty(test, response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

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
