// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moogar0880/problems"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestBasicAuthorizer_GetMiddleware(t *testing.T) {
	authorizer := &BasicAuthorizer{
		logger: zap.NewNop().Sugar(),
		users: map[string]*basicAuthUser{
			"foo": {
				// Pa55w0rd$
				PasswordHash: "$2b$12$yH/i2alYaIrVbKFkaYu5HOSf3JiZ0zPJlooufSRdO.6V3X/hXgTOq",
			},
		},
	}

	nextCalled := false
	handler := authorizer.GetMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}))

	tests := []struct {
		name     string
		username string
		password string
		wantOK   bool
	}{
		{name: "valid credentials", username: "foo", password: "Pa55w0rd$", wantOK: true},
		{name: "missing credentials"},
		{name: "incorrect password", username: "foo", password: "password"},
		{name: "unknown user", username: "bar", password: "Pa55w0rd$"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nextCalled = false
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.username != "" {
				request.SetBasicAuth(test.username, test.password)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if test.wantOK {
				assert.Equal(t, http.StatusOK, response.Code)
				assert.True(t, nextCalled)
				return
			}

			assert.Equal(t, http.StatusUnauthorized, response.Code)
			assert.Equal(t, "Basic realm=veraison", response.Header().Get("WWW-Authenticate"))

			var problem problems.DefaultProblem
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &problem))
			assert.Equal(t, "authorization failed", problem.Detail)
			assert.False(t, nextCalled)
		})
	}
}

func TestConstantTimeCompareStrings(t *testing.T) {
	tests := []struct {
		name string
		lhs  string
		rhs  string
		want int
	}{
		{name: "equal strings", lhs: "foo", rhs: "foo", want: 1},
		{name: "different same length", lhs: "foo", rhs: "bar"},
		{name: "different length", lhs: "foo", rhs: "foobar"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, constantTimeCompareStrings(test.lhs, test.rhs))
		})
	}
}
