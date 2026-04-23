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
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang/mock/gomock"
	"github.com/moogar0880/problems"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/cmw"
	mock_deps "github.com/veraison/ratsd/api/mocks"
	"github.com/veraison/ratsd/attesters/mocktsm"
	"github.com/veraison/ratsd/attesters/tsm"
	"github.com/veraison/ratsd/tokens"
	"github.com/veraison/services/log"
)

const (
	jsonType   = "application/json"
	validNonce = "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA"
)

func TestRatsdSubattesters_valid_requests(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return([]string{}).Times(1)
	dm.EXPECT().GetPluginList().Return([]string{"mock-tsm"}).Times(1)
	dm.EXPECT().GetPluginList().Return([]string{"mock-tsm", "tsm-report"}).Times(1)
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()
	dm.EXPECT().LookupByName("tsm-report").Return(&tsm.TSMPlugin{}, nil).AnyTimes()
	logger := log.Named("test")
	s := NewServer(logger, dm, "all")
	tests := []struct {
		name, response string
	}{
		{
			"no attester",
			"[]\n",
		},
		{
			"with only mocktsm attester",
			"[{\"name\":\"mock-tsm\",\"options\":[{\"data-type\":\"string\",\"name\":\"privilege_level\"}]}]\n",
		},
		{
			"with tsm and mocktsm attester",
			"[{\"name\":\"mock-tsm\",\"options\":[{\"data-type\":\"string\",\"name\":\"privilege_level\"}]},{\"name\":\"tsm-report\",\"options\":[{\"data-type\":\"string\",\"name\":\"privilege_level\"}]}]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			rb := strings.NewReader(tt.response)
			r, _ := http.NewRequest(http.MethodGet, "/ratsd/subattesters", rb)
			s.RatsdSubattesters(w, r)

			expectedCode := http.StatusOK
			expectedType := jsonType
			expectedBody := tt.response

			assert.Equal(t, expectedCode, w.Code)
			assert.Equal(t, expectedType, w.Result().Header.Get("Content-Type"))
			assert.Equal(t, expectedBody, w.Body.String())
		})
	}

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

	pluginList := []string{"mock-tsm", "tsm-report"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServer(logger, dm, "selected")
	tests := []struct{ name, body, msg string }{
		{"missing nonce", `{"noncee": "MIDBNH28iioisjPy"}`,
			"fail to retrieve nonce from the request"},
		{"invalid attester selection",
			fmt.Sprintf(`{"nonce": "%s",
		"attester-selection": "attester-slection"}`, validNonce),
			"failed to parse attester selection: json: cannot unmarshal string into" +
				` Go value of type map[string]json.RawMessage`},
		{"no attester specified in selected mode", fmt.Sprintf(`{"nonce": "%s"}`, validNonce),
			"attester-selection must contain at least one attester"},
		{"invalid attester options",
			fmt.Sprintf(`{"nonce": "%s",
			"attester-selection": {"mock-tsm":"invalid"}}`, validNonce),
			"failed to parse options for mock-tsm: json: cannot unmarshal string into" +
				` Go value of type map[string]string`},
		{"request content type unavailable",
			fmt.Sprintf(`{"nonce": "%s",
			"attester-selection": {"mock-tsm":{"content-type":"invalid"}}}`, validNonce),
			"mock-tsm does not support content type invalid"},
		{"unsupported token version",
			fmt.Sprintf(`{"nonce": "%s",
			"token-version": 3}`, validNonce),
			"unsupported token version 3"},
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

	s := NewServer(logger, dm, "all")
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

	s := NewServer(logger, dm, "all")
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
			"with null as params",
			fmt.Sprintf(`{"nonce": "%s",
				"attester-selection":{
					"mock-tsm": null
				}
			}`, validNonce),
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

func TestRatsdChares_valid_request_v2(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams

	param := fmt.Sprintf(`application/eat-ucs+cbor; eat_profile=%q`, tokens.RATSDV2Profile)
	params.Accept = &param
	logger := log.Named("test")

	pluginList := []string{"mock-tsm"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServerWithSigner(
		logger,
		dm,
		"all",
		filepath.Join("..", "ratsd.crt"),
		filepath.Join("..", "ratsd.key"),
	)
	realNonce, _ := base64.RawURLEncoding.DecodeString(validNonce)

	w := httptest.NewRecorder()
	rb := strings.NewReader(fmt.Sprintf(`{"nonce": "%s", "token-version": 2}`, validNonce))
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, param, w.Result().Header.Get("Content-Type"))

	msg := decodeCOSESign1(t, w.Body.Bytes())
	assert.NotEmpty(t, msg.Signature)

	var protected map[int64]any
	err := cbor.Unmarshal(msg.Protected, &protected)
	assert.NoError(t, err)
	assert.Equal(t, int64(-7), protected[1])

	x5chain, ok := protected[33].([]byte)
	assert.True(t, ok)
	assert.NotEmpty(t, x5chain)

	collection := &cmw.CMW{}
	err = collection.UnmarshalCBOR(msg.Payload)
	assert.NoError(t, err)
	assert.Equal(t, cmw.KindCollection, collection.GetKind())

	collectionType, err := collection.GetCollectionType()
	assert.NoError(t, err)
	assert.Equal(t, tokens.RATSDCollectionTypeV2, collectionType)

	claimsRecord, err := collection.GetCollectionItem("__ratsd")
	assert.NoError(t, err)
	assert.Equal(t, tokens.RATSDClaimsMediaTypeV2, claimsRecord.GetMonadType())

	var claimsTag cbor.Tag
	err = cbor.Unmarshal(claimsRecord.GetMonadValue(), &claimsTag)
	assert.NoError(t, err)
	assert.Equal(t, uint64(601), claimsTag.Number)

	claimsBytes, err := cbor.Marshal(claimsTag.Content)
	assert.NoError(t, err)

	var claims map[int]any
	err = cbor.Unmarshal(claimsBytes, &claims)
	assert.NoError(t, err)
	assert.Equal(t, tokens.RATSDV2Profile, claims[265])
	assert.Equal(t, realNonce, claims[10])

	c, err := collection.GetCollectionItem("mock-tsm")
	assert.NoError(t, err)
	assert.Equal(t, cmw.KindMonad, c.GetKind())
	assert.Equal(t, c.GetMonadType(), "application/vnd.veraison.configfs-tsm+json")

	tsmout := &tokens.TSMReport{}
	err = tsmout.FromJSON(c.GetMonadValue())
	assert.NoError(t, err)
	assert.Equal(t, "fake\n", tsmout.Provider)
	assert.Equal(t, tokens.BinaryString("auxblob"), tsmout.AuxBlob)

	expectedOutblob := fmt.Sprintf("privlevel: %d\ninblob: %s", 0, hex.EncodeToString([]byte(realNonce)))
	assert.Equal(t, tokens.BinaryString(expectedOutblob), tsmout.OutBlob)
}

type coseSign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

func decodeCOSESign1(t *testing.T, data []byte) *coseSign1Message {
	t.Helper()

	var tag cbor.Tag
	err := cbor.Unmarshal(data, &tag)
	assert.NoError(t, err)
	assert.Equal(t, uint64(18), tag.Number)

	content, err := cbor.Marshal(tag.Content)
	assert.NoError(t, err)

	msg := &coseSign1Message{}
	err = cbor.Unmarshal(content, msg)
	assert.NoError(t, err)

	return msg
}
