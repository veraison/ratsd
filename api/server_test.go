// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"crypto/sha3"
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
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
	mock_deps "github.com/veraison/ratsd/api/mocks"
	"github.com/veraison/ratsd/attesters/mocktsm"
	"github.com/veraison/ratsd/attesters/tsm"
	"github.com/veraison/ratsd/proto/compositor"
	ratsdtoken "github.com/veraison/ratsd/ratsd-token"
	ratsdtokenv2 "github.com/veraison/ratsd/ratsd-token-v2"
	"github.com/veraison/ratsd/tokens"
	"github.com/veraison/services/log"
)

const (
	jsonType   = "application/json"
	validNonce = "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA"
)

func decodeCharesClaims(t *testing.T, body []byte) ratsdtoken.Claims {
	t.Helper()

	var evidence ratsdtoken.Evidence
	err := json.Unmarshal(body, &evidence)
	assert.NoError(t, err)

	claims, err := evidence.GetClaims()
	assert.NoError(t, err)

	return claims
}

func decodeCharesV2(t *testing.T, body []byte) (ratsdtokenv2.Claims, cmw.CMW, []byte) {
	t.Helper()

	var evidence ratsdtokenv2.Evidence
	require.NoError(t, evidence.UnmarshalCBOR(body))

	claims, err := evidence.GetClaims()
	require.NoError(t, err)

	collection, err := evidence.GetCollection()
	require.NoError(t, err)

	return claims, collection, evidence.GetSignature()
}

func adjustNonceForTest(t *testing.T, nonce []byte, size uint32) []byte {
	t.Helper()

	adjusted := make([]byte, int(size))
	h := sha3.NewSHAKE256()
	_, err := h.Write(nonce)
	assert.NoError(t, err)
	_, err = h.Read(adjusted)
	assert.NoError(t, err)

	return adjusted
}

type testAttester struct {
	t                   *testing.T
	formats             []*compositor.Format
	expectedContentType string
	expectedNonce       []byte
	evidence            []byte
}

func (t *testAttester) GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut {
	t.t.Helper()

	assert.Equal(t.t, t.expectedContentType, in.ContentType)
	assert.Equal(t.t, t.expectedNonce, in.Nonce)

	return &compositor.EvidenceOut{
		Status:     &compositor.Status{Result: true},
		StatusCode: http.StatusOK,
		Evidence:   t.evidence,
	}
}

func (t *testAttester) GetOptions() *compositor.OptionsOut {
	return &compositor.OptionsOut{Status: &compositor.Status{Result: true}}
}

func (t *testAttester) GetSubAttesterID() *compositor.SubAttesterIDOut {
	return &compositor.SubAttesterIDOut{
		Status:        &compositor.Status{Result: true},
		SubAttesterID: &compositor.SubAttesterID{Name: "test-attester", Version: "1.0.0"},
	}
}

func (t *testAttester) GetSupportedFormats() *compositor.SupportedFormatsOut {
	return &compositor.SupportedFormatsOut{
		Status:  &compositor.Status{Result: true},
		Formats: t.formats,
	}
}

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

func TestRatsdChares_defaults_to_legacy_response_without_accept(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := log.Named("test")

	pluginList := []string{"mock-tsm"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServer(logger, dm, "all")
	w := httptest.NewRecorder()
	rb := strings.NewReader(fmt.Sprintf(`{"nonce": "%s"}`, validNonce))
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, RatsdCharesParams{})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, legacyCharesResponseMediaType, w.Result().Header.Get("Content-Type"))

	claims := decodeCharesClaims(t, w.Body.Bytes())
	profile, err := claims.EatProfile.Get()
	assert.NoError(t, err)
	assert.Equal(t, ratsdtoken.LegacyProfile, profile)
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
	expectedDetail := fmt.Sprintf(
		"wrong accept type, expect %s or %s (got %s)",
		respCt,
		v2CharesResponseMediaType,
		*(params.Accept),
	)
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
		{"invalid json", `{"nonce": "MIDBNH28iioisjPy"`,
			"unable to deserialize JSON request body"},
		{"missing nonce", `{"noncee": "MIDBNH28iioisjPy"}`,
			"fail to retrieve nonce from the request"},
		{"invalid attester selection",
			fmt.Sprintf(`{"nonce": "%s",
		"attester-selection": "attester-slection"}`, validNonce),
			"failed to parse attester selection: json: cannot unmarshal string into" +
				` Go value of type []string`},
		{"no attester specified in selected mode", fmt.Sprintf(`{"nonce": "%s"}`, validNonce),
			"attester-selection must contain at least one attester"},
		{"empty attester selection in selected mode",
			fmt.Sprintf(`{"nonce": "%s",
			"attester-selection": []}`, validNonce),
			"attester-selection must contain at least one attester"},
		{"invalid attester options",
			fmt.Sprintf(`{"nonce": "%s",
			"attester-selection": ["mock-tsm"],
			"mock-tsm":"invalid"}`, validNonce),
			"failed to parse options for mock-tsm: json: cannot unmarshal string into" +
				` Go value of type map[string]string`},
		{"request content type unavailable",
			fmt.Sprintf(`{"nonce": "%s",
			"attester-selection": ["mock-tsm"],
			"mock-tsm":{"content-type":"invalid"}}`, validNonce),
			"mock-tsm does not support content type invalid"},
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
	adjustedNonce := adjustNonceForTest(t, realNonce, 64)

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
				"mock-tsm": null
			}`, validNonce),
			0,
		},
		{
			"with params",
			fmt.Sprintf(`{"nonce": "%s",
				"mock-tsm":{
					"privilege_level":"1"
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

			claims := decodeCharesClaims(t, w.Body.Bytes())

			profile, err := claims.EatProfile.Get()
			assert.NoError(t, err)
			assert.Equal(t, ratsdtoken.LegacyProfile, profile)

			nonce := claims.GetEatNonce()
			if assert.NotNil(t, nonce) {
				assert.Equal(t, 1, nonce.Len())
				assert.Equal(t, realNonce, nonce.GetI(0))
			}
			assert.Equal(t, ratsdtoken.NonceAdjustFunctionShake256, claims.GetNonceAdjustFn())
			assert.Equal(t, map[string]uint{"mock-tsm": 64}, claims.GetNonceAdjustMap())

			collection := claims.GetCMW()
			if !assert.NotNil(t, collection) {
				return
			}
			assert.Equal(t, cmw.KindCollection, collection.GetKind())

			c, err := collection.GetCollectionItem("mock-tsm")
			assert.NoError(t, err)
			assert.Equal(t, cmw.KindMonad, c.GetKind())
			assert.Equal(t, c.GetMonadType(), tokens.TSMReportMediaTypeJSON)

			tsmout := &tokens.TSMReport{}
			tsmout.FromJSON(c.GetMonadValue())
			assert.Equal(t, "fake\n", tsmout.Provider)

			assert.Equal(t, tokens.BinaryString("auxblob"), tsmout.AuxBlob)

			expectedOutblob := fmt.Sprintf("privlevel: %d\ninblob: %s", tt.privlevel,
				hex.EncodeToString(adjustedNonce))
			assert.Equal(t, tokens.BinaryString(expectedOutblob), tsmout.OutBlob)
		})
	}
}

func TestRatsdChares_valid_request_v2(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams

	param := v2CharesResponseMediaType
	params.Accept = &param
	logger := log.Named("test")

	pluginList := []string{"mock-tsm"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServer(logger, dm, "all")
	realNonce, _ := base64.RawURLEncoding.DecodeString(validNonce)
	adjustedNonce := adjustNonceForTest(t, realNonce, 64)

	w := httptest.NewRecorder()
	rb := strings.NewReader(fmt.Sprintf(`{"nonce": "%s",
		"mock-tsm":{
			"privilege_level":"1"
		}
	}`, validNonce))
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, param, w.Result().Header.Get("Content-Type"))

	claims, collection, signature := decodeCharesV2(t, w.Body.Bytes())

	assert.Equal(t, ratsdtokenv2.Profile, claims.GetEatProfile())
	assert.Equal(t, realNonce, claims.GetEatNonce())
	assert.Equal(t, ratsdtokenv2.DefaultLeadAttesterOEMID, claims.GetOEMID())
	assert.Equal(t, ratsdtokenv2.DefaultLeadAttesterSWName, claims.GetSWName())
	assert.Equal(t, ratsdtokenv2.DefaultLeadAttesterSWVersion, claims.GetSWVersion())
	assert.Equal(t, ratsdtokenv2.NonceAdjustFunctionShake256, claims.GetNonceAdjustFn())
	assert.Equal(t, map[string]uint{"mock-tsm": 64}, claims.GetNonceAdjustMap())
	assert.Equal(t, []byte{0}, signature)

	collectionType, err := collection.GetCollectionType()
	require.NoError(t, err)
	assert.Equal(t, ratsdtokenv2.CMWCollectionType, collectionType)

	c, err := collection.GetCollectionItem("mock-tsm")
	require.NoError(t, err)
	assert.Equal(t, cmw.KindMonad, c.GetKind())
	assert.Equal(t, tokens.TSMReportMediaTypeJSON, c.GetMonadType())
	assert.Equal(t, cmw.Indicator(cmw.Evidence), c.GetMonadIndicator())

	tsmout := &tokens.TSMReport{}
	tsmout.FromJSON(c.GetMonadValue())
	assert.Equal(t, "fake\n", tsmout.Provider)
	assert.Equal(t, tokens.BinaryString("auxblob"), tsmout.AuxBlob)

	expectedOutblob := fmt.Sprintf("privlevel: %d\ninblob: %s", 1,
		hex.EncodeToString(adjustedNonce))
	assert.Equal(t, tokens.BinaryString(expectedOutblob), tsmout.OutBlob)
}

func TestRatsdChares_adjustsNonceToSelectedFormatSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams
	param := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")

	realNonce, _ := base64.RawURLEncoding.DecodeString(validNonce)
	selectedCt := "application/vnd.veraison.test-selected"
	attesterName := "format-attester"
	attester := &testAttester{
		t: t,
		formats: []*compositor.Format{
			{ContentType: "application/vnd.veraison.test-default", NonceSize: 16},
			{ContentType: selectedCt, NonceSize: 32},
		},
		expectedContentType: selectedCt,
		expectedNonce:       adjustNonceForTest(t, realNonce, 32),
		evidence:            []byte("evidence"),
	}

	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return([]string{attesterName}).AnyTimes()
	dm.EXPECT().LookupByName(attesterName).Return(attester, nil).AnyTimes()

	s := NewServer(logger, dm, "all")
	w := httptest.NewRecorder()
	rb := strings.NewReader(fmt.Sprintf(`{"nonce": "%s",
		"%s":{"content-type":"%s"}}`, validNonce, attesterName, selectedCt))
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, param, w.Result().Header.Get("Content-Type"))

	claims := decodeCharesClaims(t, w.Body.Bytes())
	assert.Equal(t, ratsdtoken.NonceAdjustFunctionShake256, claims.GetNonceAdjustFn())
	assert.Equal(t, map[string]uint{attesterName: 32}, claims.GetNonceAdjustMap())

	collection := claims.GetCMW()
	if !assert.NotNil(t, collection) {
		return
	}

	c, err := collection.GetCollectionItem(attesterName)
	assert.NoError(t, err)
	assert.Equal(t, cmw.KindMonad, c.GetKind())
	assert.Equal(t, selectedCt, c.GetMonadType())
	assert.Equal(t, []byte("evidence"), c.GetMonadValue())
}

func TestRatsdChares_valid_request_selected_attesters(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams

	param := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")

	pluginList := []string{"mock-tsm", "other-tsm"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServer(logger, dm, "selected")
	w := httptest.NewRecorder()
	rb := strings.NewReader(fmt.Sprintf(`{"nonce": "%s",
		"attester-selection": ["mock-tsm"]}`, validNonce))
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, param, w.Result().Header.Get("Content-Type"))

	claims := decodeCharesClaims(t, w.Body.Bytes())
	collection := claims.GetCMW()
	if !assert.NotNil(t, collection) {
		return
	}
	assert.Equal(t, cmw.KindCollection, collection.GetKind())

	_, err := collection.GetCollectionItem("mock-tsm")
	assert.NoError(t, err)

	_, err = collection.GetCollectionItem("other-tsm")
	assert.Error(t, err)
}

func TestRatsdChares_valid_request_selected_attesters_in_all_mode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var params RatsdCharesParams

	param := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	params.Accept = &param
	logger := log.Named("test")

	pluginList := []string{"mock-tsm", "other-tsm"}
	dm := mock_deps.NewMockIManager(ctrl)
	dm.EXPECT().GetPluginList().Return(pluginList).AnyTimes()
	dm.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil).AnyTimes()

	s := NewServer(logger, dm, "all")
	w := httptest.NewRecorder()
	rb := strings.NewReader(fmt.Sprintf(`{"nonce": "%s",
		"attester-selection": ["mock-tsm"]}`, validNonce))
	r, _ := http.NewRequest(http.MethodPost, "/ratsd/chares", rb)
	r.Header.Add("Content-Type", ApplicationvndVeraisonCharesJson)
	s.RatsdChares(w, r, params)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, param, w.Result().Header.Get("Content-Type"))

	claims := decodeCharesClaims(t, w.Body.Bytes())
	collection := claims.GetCMW()
	if !assert.NotNil(t, collection) {
		return
	}
	assert.Equal(t, cmw.KindCollection, collection.GetKind())

	_, err := collection.GetCollectionItem("mock-tsm")
	assert.NoError(t, err)

	_, err = collection.GetCollectionItem("other-tsm")
	assert.Error(t, err)
}
