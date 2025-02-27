// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"errors"
	"net/http"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type PassthroughAuthorizer struct {
	logger *zap.SugaredLogger
}

func NewPassthroughAuthorizer(logger *zap.SugaredLogger) IAuthorizer {
	return &PassthroughAuthorizer{logger: logger}
}

func (o *PassthroughAuthorizer) Init(v *viper.Viper, logger *zap.SugaredLogger) error {
	if logger == nil {
		return errors.New("nil logger")
	}
	o.logger = logger
	return nil
}

func (o *PassthroughAuthorizer) Close() error {
	return nil
}

func (o *PassthroughAuthorizer) GetMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			o.logger.Debugw("passthrough", "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
}
