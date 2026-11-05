package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/moogar0880/problems"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock_deps "github.com/veraison/ratsd/api/mocks"
	"github.com/veraison/ratsd/attesters/mocktsm"
	"github.com/veraison/ratsd/config"
	"github.com/veraison/ratsd/log"
	"github.com/veraison/ratsd/proto/compositor"
)

func TestRatsdDiscovery(test *testing.T) {
	spec, err := GetSpec()
	require.NoError(test, err)
	require.NoError(test, spec.Validate(context.Background()))
	discoveryPath := spec.Paths.Find("/.well-known/veraison/ratsd")
	require.NotNil(test, discoveryPath)
	require.NotNil(test, discoveryPath.Get)
	require.NotNil(test, discoveryPath.Get.Security)
	assert.Empty(test, *discoveryPath.Get.Security)

	for _, mode := range []string{"all", "selected"} {
		for _, plugins := range [][]string{nil, {"mock-tsm", "no-options"}} {
			name := mode + "/empty"
			if len(plugins) > 0 {
				name = mode + "/attesters"
			}
			test.Run(name, func(test *testing.T) {
				controller := gomock.NewController(test)
				manager := mock_deps.NewMockIManager(controller)
				manager.EXPECT().GetPluginList().Return(plugins)
				if len(plugins) > 0 {
					manager.EXPECT().LookupByName("mock-tsm").Return(mocktsm.GetPlugin(), nil)
					attester := mock_deps.NewMockIPluggable(controller)
					manager.EXPECT().LookupByName("no-options").Return(attester, nil)
					attester.EXPECT().GetOptions().Return(&compositor.OptionsOut{
						Status: &compositor.Status{Result: true},
					})
				}
				handler := Handler(NewServer(log.Named("test"), manager, mode))
				request := httptest.NewRequest(http.MethodGet, "/.well-known/veraison/ratsd", nil)
				response := httptest.NewRecorder()
				started := time.Now()
				handler.ServeHTTP(response, request)

				require.Equal(test, http.StatusOK, response.Code)
				assert.Equal(test, "application/vnd.veraison.discovery+json", response.Header().Get("Content-Type"))
				assert.Equal(test, "max-age=60", response.Header().Get("Cache-Control"))
				expires, err := http.ParseTime(response.Header().Get("Expires"))
				require.NoError(test, err)
				assert.WithinRange(test, expires, started.Add(59*time.Second), time.Now().Add(60*time.Second))

				var document Discovery
				require.NoError(test, json.Unmarshal(response.Body.Bytes(), &document))
				assert.Equal(test, config.Version, document.Version)
				assert.Equal(test, DiscoveryServiceState("READY"), document.ServiceState)
				assert.Equal(test, []string{"shake-128", "shake-256"}, document.NonceAdjustFunctions)
				assert.Contains(test, document.NonceAdjustFunctions, defaultNonceAdjustFunction)
				require.NotNil(test, document.Subattesters)
				require.Len(test, document.Subattesters, len(plugins))
				if len(plugins) > 0 {
					assert.Equal(test, "mock-tsm", document.Subattesters[0].Name)
					require.NotNil(test, document.Subattesters[0].Options)
					assert.Equal(test, []Option{{Name: "privilege_level", DataType: String}}, *document.Subattesters[0].Options)
					assert.Equal(test, "no-options", document.Subattesters[1].Name)
					require.NotNil(test, document.Subattesters[1].Options)
					assert.Empty(test, *document.Subattesters[1].Options)
				}

				endpoint := document.ApiEndpoints["chares"]
				require.Equal(test, "/ratsd/chares", endpoint)
				operation := spec.Paths.Find(endpoint).Post
				require.NotNil(test, operation)
				mediaTypes := []string{}
				for mediaType := range operation.Responses.Status(http.StatusOK).Value.Content {
					mediaTypes = append(mediaTypes, mediaType)
				}
				assert.ElementsMatch(test, mediaTypes, document.MediaTypes)

				var body any
				require.NoError(test, json.Unmarshal(response.Body.Bytes(), &body))
				schema := discoveryPath.Get.Responses.Status(http.StatusOK).Value.Content[discoveryMediaType].Schema.Value
				require.NoError(test, schema.VisitJSON(body))
				response = httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, endpoint, nil))
				assert.Equal(test, http.StatusBadRequest, response.Code)
			})
		}
	}
}

func TestDiscoveryAttesterFailures(test *testing.T) {
	for _, endpoint := range []string{"/.well-known/veraison/ratsd", "/ratsd/subattesters"} {
		for _, testCase := range []struct {
			name       string
			lookupErr  error
			options    *compositor.OptionsOut
			wantDetail string
		}{
			{
				name:       "lookup failure",
				lookupErr:  errors.New("plugin unavailable"),
				wantDetail: "failed to get handle from mock-tsm: plugin unavailable",
			},
			{
				name: "options failure",
				options: &compositor.OptionsOut{
					Status: &compositor.Status{Error: "plugin disconnected"},
				},
				wantDetail: "failed to get options from mock-tsm: plugin disconnected",
			},
			{
				name:       "missing options response",
				wantDetail: "failed to get options from mock-tsm:",
			},
		} {
			test.Run(endpoint+"/"+testCase.name, func(test *testing.T) {
				controller := gomock.NewController(test)
				manager := mock_deps.NewMockIManager(controller)
				manager.EXPECT().GetPluginList().Return([]string{"mock-tsm"})
				if testCase.lookupErr != nil {
					manager.EXPECT().LookupByName("mock-tsm").Return(nil, testCase.lookupErr)
				} else {
					attester := mock_deps.NewMockIPluggable(controller)
					manager.EXPECT().LookupByName("mock-tsm").Return(attester, nil)
					attester.EXPECT().GetOptions().Return(testCase.options)
				}
				handler := Handler(NewServer(log.Named("test"), manager, "all"))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, endpoint, nil))

				assert.Equal(test, http.StatusInternalServerError, response.Code)
				assert.Equal(test, problems.ProblemMediaType, response.Header().Get("Content-Type"))
				assert.Empty(test, response.Header().Get("Cache-Control"))
				assert.Empty(test, response.Header().Get("Expires"))
				var problem problems.DefaultProblem
				require.NoError(test, json.Unmarshal(response.Body.Bytes(), &problem))
				assert.Contains(test, problem.Detail, testCase.wantDetail)
			})
		}
	}
}
