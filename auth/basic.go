// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/viper"
	"github.com/veraison/services/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type basicAuthUser struct {
	PasswordHash string `mapstructure:"password"`
}

func newBasicAuthUser(m map[string]interface{}) (*basicAuthUser, error) {
	var newUser basicAuthUser

	passRaw, ok := m["password"]
	if !ok {
		return nil, errors.New("password not set")
	}

	switch t := passRaw.(type) {
	case string:
		newUser.PasswordHash = t
	default:
		return nil, fmt.Errorf("invalid password: expected string found %T", t)
	}

	return &newUser, nil
}

type BasicAuthorizer struct {
	logger *zap.SugaredLogger
	users  map[string]*basicAuthUser
}

func (o *BasicAuthorizer) Init(v *viper.Viper, logger *zap.SugaredLogger) error {
	if logger == nil {
		return errors.New("nil logger")
	}
	o.logger = logger

	o.users = make(map[string]*basicAuthUser)
	if rawUsers := v.GetStringMap("users"); rawUsers != nil {
		for name, rawUser := range rawUsers {
			switch t := rawUser.(type) {
			case map[string]interface{}:
				newUser, err := newBasicAuthUser(t)
				if err != nil {
					return fmt.Errorf("invalid user %q: %w", name, err)

				}
				o.logger.Debugw("registered user",
					"user", name,
					"hashed password", newUser.PasswordHash,
				)
				o.users[name] = newUser
			default:
				return fmt.Errorf(
					"invalid user %q: expected map[string]interface{}, got %T",
					name, t,
				)
			}
		}
	}

	return nil
}

func (o *BasicAuthorizer) Close() error {
	return nil
}

func (o *BasicAuthorizer) GetMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			o.logger.Debugw("auth basic", "path", r.URL.Path)

			userName, password, hasAuth := r.BasicAuth()
			if !hasAuth {
				w.Header().Set("WWW-Authenticate", "Basic realm=veraison")
				ReportProblem(o.logger, w, "no Basic Authorizaiton given")
				return
			}

			userInfo, ok := o.users[userName]
			if !ok {
				w.Header().Set("WWW-Authenticate", "Basic realm=veraison")
				ReportProblem(o.logger, w, fmt.Sprintf("no such user: %s", userName))
				return
			}

			if err := bcrypt.CompareHashAndPassword(
				[]byte(userInfo.PasswordHash),
				[]byte(password),
			); err != nil {
				o.logger.Debugf("password check failed: %v", err)
				w.Header().Set("WWW-Authenticate", "Basic realm=veraison")
				ReportProblem(o.logger, w, "wrong username or password")
				return
			}

			log.Debugw("user authenticated", "user", userName)
			next.ServeHTTP(w, r)
		})
}
