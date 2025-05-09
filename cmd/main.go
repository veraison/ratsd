// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"net/http"

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
	ListenAddr string `mapstructure:"listen-addr" valid:"dialstring"`
	Protocol   string `mapstructure:"protocol" valid:"in(http|https)"`
	Cert       string `mapstructure:"cert" config:"zerodefault"`
	CertKey    string `mapstructure:"cert-key" config:"zerodefault"`
	PluginDir  string `mapstructure:"plugin-dir" config:"zerodefault"`
}

func (o cfg) Validate() error {
	if o.Protocol == "https" && (o.Cert == "" || o.CertKey == "") {
		return errors.New(`both cert and cert-key must be specified when protocol is "https"`)
	}

	return nil
}

func main() {
	config.CmdLine()

	v, err := config.ReadRawConfig(*config.File, false)
	if err != nil {
		log.Fatalf("Could not read config sources: %v", err)
	}

	cfg := cfg{
		ListenAddr: DefaultListenAddr,
		Protocol:   "https",
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

	// Load sub-attesters from the path specified in config.yaml
	pluginManager, err := plugin.CreateGoPluginManager(
		cfg.PluginDir, log.Named("plugin"))

	if err != nil {
		log.Fatalf("could not create the plugin manager: %v", err)
	}

	log.Info("Loaded sub-attesters:", pluginManager.GetPluginList())

	svr := api.NewServer(log.Named("api"), pluginManager)
	r := http.NewServeMux()
	options := api.StdHTTPServerOptions{
		BaseRouter:  r,
		Middlewares: []api.MiddlewareFunc{authorizer.GetMiddleware},
	}
	h := api.HandlerWithOptions(svr, options)

	s := &http.Server{
		Handler: h,
		Addr:    cfg.ListenAddr,
	}

	if cfg.Protocol == "https" {
		log.Infow("initializing ratsd HTTPS service", "address", cfg.ListenAddr)
		log.Fatal(s.ListenAndServeTLS(cfg.Cert, cfg.CertKey))
	} else {
		log.Infow("initializing ratsd HTTP service", "address", cfg.ListenAddr)
		log.Fatal(s.ListenAndServe())
	}
}
