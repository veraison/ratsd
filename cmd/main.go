// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/veraison/ratsd/api"
	"github.com/veraison/ratsd/auth"
	"github.com/veraison/ratsd/plugin"
	"github.com/veraison/services/config"
	"github.com/veraison/services/log"
)

var (
	DefaultListenAddr = "localhost:8895"
)

const (
	protocolHTTPS     = "https"
	readHeaderTimeout = 10 * time.Second
)

type cfg struct {
	ListenAddr   string `mapstructure:"listen-addr" valid:"dialstring"`
	Protocol     string `mapstructure:"protocol" valid:"in(http|https)"`
	Cert         string `mapstructure:"cert" config:"zerodefault"`
	CertKey      string `mapstructure:"cert-key" config:"zerodefault"`
	PluginDir    string `mapstructure:"plugin-dir" config:"zerodefault"`
	ListOptions  string `mapstructure:"list-options" valid:"in(all|selected)"`
	SecureLoader bool   `mapstructure:"secure-loader" config:"zerodefault"`
}

func (o cfg) Validate() error {
	if o.Protocol == protocolHTTPS && (o.Cert == "" || o.CertKey == "") {
		return errors.New(`both cert and cert-key must be specified when protocol is "https"`)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	config.CmdLine()

	v, err := config.ReadRawConfig(*config.File, false)
	if err != nil {
		return fmt.Errorf("could not read config sources: %w", err)
	}

	cfg := cfg{
		ListenAddr: DefaultListenAddr,
		Protocol:   protocolHTTPS,
	}

	subs, err := config.GetSubs(v, "ratsd", "*logging", "*auth")
	if err != nil {
		return err
	}

	classifiers := map[string]interface{}{"ratsd": "core"}
	if err := log.Init(subs["logging"], classifiers); err != nil {
		return fmt.Errorf("could not configure logging: %w", err)
	}

	authorizer, err := auth.NewAuthorizer(subs["auth"], log.Named("auth"))
	if err != nil {
		return fmt.Errorf("could not init authorizer: %w", err)
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
		return fmt.Errorf("could not load config: %w", err)
	}

	// Load sub-attesters from the path specified in config.yaml
	pluginLoader, err := plugin.CreateGoPluginLoader(cfg.PluginDir, log.Named("plugin"))
	if err != nil {
		return fmt.Errorf("could not create the plugin loader: %w", err)
	}
	if cfg.SecureLoader {
		subs, err := config.GetSubs(v, "plugins")
		if err != nil {
			return fmt.Errorf("failed to enable secure loader: %w", err)
		}
		if err := pluginLoader.SetChecksum(subs["plugins"]); err != nil {
			return fmt.Errorf("secure loader failed to set plugin checksum: %w", err)
		}
	}

	pluginManager, err := plugin.CreateGoPluginManagerWithLoader(
		pluginLoader, log.Named("plugin"))

	if err != nil {
		return fmt.Errorf("could not create the plugin manager: %w", err)
	}

	log.Info("Loaded sub-attesters:", pluginManager.GetPluginList())

	svr := api.NewServer(log.Named("api"), pluginManager, cfg.ListOptions)
	r := http.NewServeMux()
	options := api.StdHTTPServerOptions{
		BaseRouter:  r,
		Middlewares: []api.MiddlewareFunc{authorizer.GetMiddleware},
	}
	h := api.HandlerWithOptions(svr, options)

	s := &http.Server{
		Handler:           h,
		Addr:              cfg.ListenAddr,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	if cfg.Protocol == protocolHTTPS {
		log.Infow("initializing ratsd HTTPS service", "address", cfg.ListenAddr)
		return s.ListenAndServeTLS(cfg.Cert, cfg.CertKey)
	}

	log.Infow("initializing ratsd HTTP service", "address", cfg.ListenAddr)
	return s.ListenAndServe()
}
