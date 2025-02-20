// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/moogar0880/problems"
	"github.com/stretchr/testify/assert"
	mock_deps "github.com/veraison/ratsd/api/mocks"
	"github.com/veraison/services/log"
)

const (
	jsonType   = "application/json"
	validNonce = "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHg="
)

func TestRatsdChares_missing_auth_header(t *testing.T) {
	expectedCode := http.StatusUnauthorized
	expectedType := problems.ProblemMediaType
	expectedBody := &problems.DefaultProblem{
		Type:   string(TagGithubCom2024VeraisonratsdErrorUnauthorized),
		Title:  string(AccessUnauthorized),
		Status: http.StatusUnauthorized,
		Detail: "wrong or missing authorization header",
	}

	var params RatsdCharesParams
	logger := log.Named("test")
	s := &Server{logger: logger}
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", http.NoBody)
	s.RatsdChares(w, r, params)

	var body problems.DefaultProblem
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	assert.Equal(t, expectedCode, w.Code)
	assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))
	assert.Equal(t, expectedBody, &body)
}

func TestRatsdChares_wrong_content_type(t *testing.T) {
	expectedCode := http.StatusBadRequest
	expectedType := problems.ProblemMediaType
	expectedBody := &problems.DefaultProblem{
		Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
		Title:  string(InvalidRequest),
		Status: http.StatusBadRequest,
		Detail: fmt.Sprintf("wrong content type, expect %s (got %s)", ApplicationvndVeraisonCharesJson, jsonType),
	}

	var params RatsdCharesParams
	logger := log.Named("test")
	s := &Server{logger: logger}
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", http.NoBody)
	r.Header.Add("Authorization", ExpectedAuth)
	r.Header.Add("Content-Type", jsonType)
	s.RatsdChares(w, r, params)

	var body problems.DefaultProblem
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	assert.Equal(t, expectedCode, w.Code)
	assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))
	assert.Equal(t, expectedBody, &body)
}

func TestRatsdChares_wrong_accept_type(t *testing.T) {
	var params RatsdCharesParams

	param := jsonType
	params.Accept = &param
	logger := log.Named("test")
	s := &Server{logger: logger}
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", http.NoBody)
	r.Header.Add("Authorization", ExpectedAuth)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	respCt := fmt.Sprintf(`application/eat+jwt; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	expectedCode := http.StatusNotAcceptable
	expectedType := problems.ProblemMediaType
	expectedDetail := fmt.Sprintf("wrong accept type, expect %s (got %s)", respCt, *(params.Accept))
	expectedBody := problems.NewDetailedProblem(http.StatusNotAcceptable, expectedDetail)

	var body problems.DefaultProblem
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	assert.Equal(t, expectedCode, w.Code)
	assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))
	assert.Equal(t, expectedBody, &body)
}

func TestRatsdChares_missing_nonce(t *testing.T) {
	var params RatsdCharesParams

	param := fmt.Sprintf(`application/eat+jwt; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")
	s := &Server{logger: logger}
	w := httptest.NewRecorder()
	rb := strings.NewReader("{\"noncee\": \"MIDBNH28iioisjPy\"}")
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Authorization", ExpectedAuth)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	expectedCode := http.StatusBadRequest
	expectedType := problems.ProblemMediaType
	expectedBody := &problems.DefaultProblem{
		Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
		Title:  string(InvalidRequest),
		Status: http.StatusBadRequest,
		Detail: "fail to retrieve nonce from the request",
	}

	var body problems.DefaultProblem
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	assert.Equal(t, expectedCode, w.Code)
	assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))
	assert.Equal(t, expectedBody, &body)
}

func TestRatsdChares_valid_request_no_available_attester(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams

	param := fmt.Sprintf(`application/eat+jwt; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")

	pluginList := []string{}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList)

	s := NewServer(logger, dm)
	w := httptest.NewRecorder()
	rs := fmt.Sprintf("{\"nonce\": \"%s\"}", validNonce)
	rb := strings.NewReader(rs)
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Authorization", ExpectedAuth)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	expectedCode := http.StatusOK
	expectedType := param

	assert.Equal(t, expectedCode, w.Code)
	assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))

	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	assert.Equal(t, string(TagGithubCom2024Veraisonratsd), out["eat_profile"])
	assert.Equal(t, validNonce, out["eat_nonce"])
	assert.Contains(t, out, "cmw")
	assert.Empty(t, out["cmw"])
}
