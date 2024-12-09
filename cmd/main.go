package main

import (
	"errors"

	"github.com/veraison/services/config"
	"github.com/veraison/services/log"
)

var (
	DefaultListenAddr = "localhost:8888"
)

type cfg struct {
	ListenAddr string `mapstructure:"listen-addr" valid:"dialstring"`
	Protocol   string `mapstructure:"protocol" valid:"in(http|https)"`
	Cert       string `mapstructure:"cert" config:"zerodefault"`
	CertKey    string `mapstructure:"cert-key" config:"zerodefault"`
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
		Protocol:   "http",
	}

	subs, err := config.GetSubs(v, "ratsd", "*logging")
	if err != nil {
		log.Fatal(err)
	}

	classifiers := map[string]interface{}{"ratsd": "core"}
	if err := log.Init(subs["logging"], classifiers); err != nil {
		log.Fatalf("could not configure logging: %v", err)
	}

	log.Infow("Initializing ratsd core")

	loader := config.NewLoader(&cfg)
	if err = loader.LoadFromViper(subs["ratsd"]); err != nil {
		log.Fatalf("Could not load config: %v", err)
	}
}
