// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"net/http"
	"os"

	"github.com/spf13/pflag"
	"github.com/veraison/ratsd/api"
	"github.com/veraison/ratsd/auth"
	"github.com/veraison/ratsd/plugin"
	"github.com/veraison/services/config"
	"github.com/veraison/services/log"
)

var (
	DefaultListenAddr = "localhost:8895"
)

type cfg struct {
	ListenAddr  string `mapstructure:"listen-addr" valid:"dialstring"`
	Protocol    string `mapstructure:"protocol" valid:"in(http|https)"`
	Cert        string `mapstructure:"cert" config:"zerodefault"`
	CertKey     string `mapstructure:"cert-key" config:"zerodefault"`
	PluginDir   string `mapstructure:"plugin-dir" config:"zerodefault"`
	ListOptions string `mapstructure:"list-options" valid:"in(all|selected)"`
	SecureLoader  bool   `mapstructure:"secure-loader" config:"zerodefault"`
	// Mock mode fields (not loaded from config)
	MockMode     bool   
	EvidenceFile string 
}

func (o cfg) Validate() error {
	if o.Protocol == "https" && (o.Cert == "" || o.CertKey == "") {
		return errors.New(`both cert and cert-key must be specified when protocol is "https"`)
	}

	return nil
}

func main() {
	// Check for mock mode before processing config
	mockMode := false
	var evidenceFile string
	configFile := "config.yaml"
	
	if len(os.Args) > 1 && os.Args[1] == "mock" {
		mockMode = true
		// Parse mock subcommand flags
		mockCmd := pflag.NewFlagSet("mock", pflag.ExitOnError)
		mockCmd.StringVar(&evidenceFile, "evidence", "", "Path to CMW evidence file")
		mockCmd.StringVar(&configFile, "config", "config.yaml", "configuration file")
		mockCmd.Parse(os.Args[2:])
		
		if evidenceFile == "" {
			log.Fatal("--evidence flag is required for mock mode")
		}
	} else {
		config.CmdLine()
		configFile = *config.File
	}

	v, err := config.ReadRawConfig(configFile, false)
	if err != nil {
		log.Fatalf("Could not read config sources: %v", err)
	}

	cfg := cfg{
		ListenAddr:   DefaultListenAddr,
		Protocol:     "https",
		MockMode:     mockMode,
		EvidenceFile: evidenceFile,
	}

	subs, err := config.GetSubs(v, "ratsd", "*logging", "*auth")
	if err != nil {
		log.Fatal(err)
	}

	classifiers := map[string]interface{}{"ratsd": "core"}
	if err := log.Init(subs["logging"], classifiers); err != nil {
		log.Fatalf("could not configure logging: %v", err)
	}

	authorizer, err := auth.NewAuthorizer(subs["auth"], log.Named("auth"))
	if err != nil {
		log.Fatalf("could not init authorizer: %v", err)
	}
	defer func() {
		err := authorizer.Close()
		if err != nil {
			log.Errorf("Could not close authorizer: %v", err)
		}
	}()

	log.Infow("Initializing ratsd core")

	loader := config.NewLoader(&cfg)
	if err = loader.LoadFromViper(subs["ratsd"]); err != nil {
		log.Fatalf("Could not load config: %v", err)
	}

	var svr *api.Server
	
	if cfg.MockMode {
		log.Infow("Initializing ratsd in mock mode", "evidence-file", cfg.EvidenceFile)
		svr = api.NewMockServer(log.Named("api"), cfg.EvidenceFile)
	} else {
		// Load sub-attesters from the path specified in config.yaml
		pluginLoader, err := plugin.CreateGoPluginLoader(cfg.PluginDir, log.Named("plugin"))
		if err != nil {
			log.Fatalf("could not create the plugin loader: %v", err)
		}
		if cfg.SecureLoader {
			subs, err := config.GetSubs(v, "plugins")
			if err != nil {
				log.Fatalf("failed to enable secure loader: %v", err)
			}
			if err := pluginLoader.SetChecksum(subs["plugins"]); err != nil {
				log.Fatalf("secure loader failed to set plugin checksum: %v", err)
			}
		}

		pluginManager, err := plugin.CreateGoPluginManagerWithLoader(
			pluginLoader, log.Named("plugin"))

		if err != nil {
			log.Fatalf("could not create the plugin manager: %v", err)
		}

		log.Info("Loaded sub-attesters:", pluginManager.GetPluginList())
		svr = api.NewServer(log.Named("api"), pluginManager, cfg.ListOptions)
	}
	log.Info("Setting up HTTP router and middleware")
	r := http.NewServeMux()
	options := api.StdHTTPServerOptions{
		BaseRouter:  r,
		Middlewares: []api.MiddlewareFunc{authorizer.GetMiddleware},
	}
	h := api.HandlerWithOptions(svr, options)
	log.Info("HTTP handler created successfully")

	s := &http.Server{
		Handler: h,
		Addr:    cfg.ListenAddr,
	}
	log.Infof("HTTP server configured with address: %s", cfg.ListenAddr)

	if cfg.Protocol == "https" {
		log.Infow("initializing ratsd HTTPS service", "address", cfg.ListenAddr)
		if err := s.ListenAndServeTLS(cfg.Cert, cfg.CertKey); err != nil {
			log.Fatalf("Failed to start HTTPS server: %v", err)
		}
	} else {
		log.Infow("initializing ratsd HTTP service", "address", cfg.ListenAddr)
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}
}
