// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/moogar0880/problems"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/cmw"
	mock_deps "github.com/veraison/ratsd/api/mocks"
	"github.com/veraison/ratsd/attesters/mocktsm"
	"github.com/veraison/services/log"
)

const (
	jsonType   = "application/json"
	validNonce = "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA"
)

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
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	respCt := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
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

	param := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")
	s := &Server{logger: logger}
	w := httptest.NewRecorder()
	rb := strings.NewReader("{\"noncee\": \"MIDBNH28iioisjPy\"}")
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
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

	param := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
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
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	expectedCode := http.StatusInternalServerError
	expectedType := problems.ProblemMediaType
	expectedDetail := "no sub-attester available"
	expectedBody := problems.NewDetailedProblem(http.StatusInternalServerError, expectedDetail)

	var body problems.DefaultProblem
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	assert.Equal(t, expectedCode, w.Code)
	assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))
	assert.Equal(t, expectedBody, &body)
}

func TestRatsdChares_valid_request(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams

	param := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")

	pluginList := []string{"mock-tsm"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList)
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil)

	s := NewServer(logger, dm)
	w := httptest.NewRecorder()
	rs := fmt.Sprintf("{\"nonce\": \"%s\"}", validNonce)
	rb := strings.NewReader(rs)
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	expectedCode := http.StatusOK
	expectedType := param

	assert.Equal(t, expectedCode, w.Code)
	assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))

	var out map[string]string
	json.Unmarshal(w.Body.Bytes(), &out)
	assert.Equal(t, string(TagGithubCom2024Veraisonratsd), out["eat_profile"])
	assert.Equal(t, validNonce, out["eat_nonce"])
	assert.Contains(t, out, "cmw")

	data, err := base64.StdEncoding.DecodeString(out["cmw"])
	assert.NoError(t, err)

	collection := &cmw.CMW{}
	err = collection.UnmarshalJSON([]byte(data))
	assert.NoError(t, err)
	assert.Equal(t, cmw.KindCollection, collection.GetKind())

	c, err := collection.GetCollectionItem("mock-tsm")
	assert.NoError(t, err)
	assert.Equal(t, cmw.KindMonad, c.GetKind())
	assert.Equal(t, c.GetMonadType(), "application/vnd.veraison.configfs-tsm+json")

	var tsmout map[string]string
	json.Unmarshal(c.GetMonadValue(), &tsmout)
	assert.Equal(t, "fake\n", tsmout["provider"])

	auxblob, err := base64.RawURLEncoding.DecodeString(tsmout["auxblob"])
	assert.Equal(t, []byte("auxblob"), auxblob)

	outblob, err := base64.RawURLEncoding.DecodeString(tsmout["outblob"])
	assert.NoError(t, err)
	realNonce, _ := base64.RawURLEncoding.DecodeString(validNonce)
	expectedOutblob := fmt.Sprintf("privlevel: 0\ninblob: %s", hex.EncodeToString([]byte(realNonce)))
	assert.Equal(t, []byte(expectedOutblob), outblob)
}
