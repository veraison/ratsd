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
	"github.com/veraison/ratsd/tokens"
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

func TestRatsdChares_invalid_body(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams

	param := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")

	pluginList := []string{"mock-tsm"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServer(logger, dm)
	tests := []struct{ name, body, msg string }{
		{"missing nonce", `{"noncee": "MIDBNH28iioisjPy"}`,
			"fail to retrieve nonce from the request"},
		{"invalid attester selecton",
			fmt.Sprintf(`{"nonce": "%s",
		"attester-selection": "attester-slection"}`, validNonce),
			"failed to parse attester selection: json: cannot unmarshal string into" +
				` Go value of type map[string]json.RawMessage`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			rb := strings.NewReader(tt.body)
			r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
			r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
			s.RatsdChares(w, r, params)

			expectedCode := http.StatusBadRequest
			expectedType := problems.ProblemMediaType
			expectedBody := &problems.DefaultProblem{
				Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
				Title:  string(InvalidRequest),
				Status: http.StatusBadRequest,
				Detail: tt.msg,
			}

			var body problems.DefaultProblem
			_ = json.Unmarshal(w.Body.Bytes(), &body)

			assert.Equal(t, expectedCode, w.Code)
			assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))
			assert.Equal(t, expectedBody, &body)
		})
	}
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
	rs := fmt.Sprintf(`{"nonce": "%s"}`, validNonce)
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
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServer(logger, dm)
	realNonce, _ := base64.RawURLEncoding.DecodeString(validNonce)

	tests := []struct {
		name, query string
		privlevel   int
	}{
		{
			"no params",
			fmt.Sprintf(`{"nonce": "%s"}`, validNonce),
			0,
		},
		{
			"with params",
			fmt.Sprintf(`{"nonce": "%s",
				"attester-selection":{
					"mock-tsm":{
						"privilege_level":"1"
					}
				}
			}`, validNonce),
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			rb := strings.NewReader(tt.query)
			r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
			r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
			s.RatsdChares(w, r, params)

			expectedCode := http.StatusOK
			expectedType := param

			assert.Equal(t, expectedCode, w.Code)
			assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))

			var out map[string]string
			err := json.Unmarshal(w.Body.Bytes(), &out)
			assert.NoError(t, err)
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

			tsmout := &tokens.TSMReport{}
			tsmout.FromJSON(c.GetMonadValue())
			assert.Equal(t, "fake\n", tsmout.Provider)

			assert.Equal(t, tokens.BinaryString("auxblob"), tsmout.AuxBlob)

			expectedOutblob := fmt.Sprintf("privlevel: %d\ninblob: %s", tt.privlevel,
				hex.EncodeToString([]byte(realNonce)))
			assert.Equal(t, tokens.BinaryString(expectedOutblob), tsmout.OutBlob)
		})
	}
}
