// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestNewMockServer(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	
	// Create a temporary evidence file
	evidenceData := MockEvidenceData{
		Attesters: map[string]MockAttesterEvidence{
			"test-attester": {
				ContentType: "application/test",
				Evidence:    "dGVzdC1ldmlkZW5jZQ==", // base64("test-evidence")
			},
		},
	}
	
	evidenceJSON, err := json.Marshal(evidenceData)
	require.NoError(t, err)
	
	tmpFile, err := os.CreateTemp("", "mock-evidence-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	_, err = tmpFile.Write(evidenceJSON)
	require.NoError(t, err)
	tmpFile.Close()
	
	// Test creating mock server
	server := NewMockServer(logger, tmpFile.Name())
	
	assert.True(t, server.mockMode)
	assert.NotNil(t, server.mockEvidence)
	assert.Nil(t, server.manager)
}

func TestMockEvidenceHandler(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	
	// Create mock evidence data
	evidenceData := MockEvidenceData{
		Attesters: map[string]MockAttesterEvidence{
			"mock-tsm": {
				ContentType: "application/vnd.veraison.configfs-tsm+json",
				Evidence:    "eyJ0ZXN0IjoibW9jay1kYXRhIn0=", // base64 encoded JSON
			},
		},
	}
	
	evidenceJSON, err := json.Marshal(evidenceData)
	require.NoError(t, err)
	
	tmpFile, err := os.CreateTemp("", "mock-evidence-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	_, err = tmpFile.Write(evidenceJSON)
	require.NoError(t, err)
	tmpFile.Close()
	
	server := NewMockServer(logger, tmpFile.Name())
	
	// Create test request
	requestData := ChaResRequest{
		Nonce: "dGVzdC1ub25jZQ==", // base64("test-nonce")
	}
	
	requestJSON, err := json.Marshal(requestData)
	require.NoError(t, err)
	
	req := httptest.NewRequest("POST", "/ratsd/chares", bytes.NewReader(requestJSON))
	req.Header.Set("Content-Type", ApplicationvndVeraisonCharesJson)
	accept := "application/eat-ucs+json; eat_profile=\"tag:github.com,2024:veraison/ratsd\""
	
	w := httptest.NewRecorder()
	
	// Test the mock handler
	server.RatsdChares(w, req, RatsdCharesParams{Accept: &accept})
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Equal(t, "tag:github.com,2024:veraison/ratsd", response["eat_profile"])
	assert.Equal(t, "dGVzdC1ub25jZQ==", response["eat_nonce"])
	assert.Contains(t, response, "cmw")
}

func TestMockSubattesters(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	
	// Create minimal evidence file for mock server
	evidenceData := MockEvidenceData{
		Attesters: map[string]MockAttesterEvidence{
			"test-attester": {
				ContentType: "application/test",
				Evidence:    "dGVzdA==",
			},
		},
	}
	
	evidenceJSON, err := json.Marshal(evidenceData)
	require.NoError(t, err)
	
	tmpFile, err := os.CreateTemp("", "mock-evidence-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	_, err = tmpFile.Write(evidenceJSON)
	require.NoError(t, err)
	tmpFile.Close()
	
	server := NewMockServer(logger, tmpFile.Name())
	
	req := httptest.NewRequest("GET", "/ratsd/subattesters", nil)
	w := httptest.NewRecorder()
	
	server.RatsdSubattesters(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, JsonType, w.Header().Get("Content-Type"))
	
	var response []SubAttester
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Len(t, response, 1)
	assert.Equal(t, "mock-attester", response[0].Name)
	assert.Empty(t, *response[0].Options)
}

// Note: Testing error cases with NewMockServer is difficult because it uses log.Fatalf
// which calls os.Exit(). In a real scenario, these would be caught during startup.
// For comprehensive testing, we would need to refactor NewMockServer to return errors
// instead of using log.Fatalf.

func TestMockServerValidation(t *testing.T) {
	// Test with empty attesters file
	evidenceData := MockEvidenceData{
		Attesters: map[string]MockAttesterEvidence{},
	}
	
	evidenceJSON, err := json.Marshal(evidenceData)
	require.NoError(t, err)
	
	tmpFile, err := os.CreateTemp("", "empty-evidence-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	
	_, err = tmpFile.Write(evidenceJSON)
	require.NoError(t, err)
	tmpFile.Close()
	
	// This would fail in real usage due to empty attesters, but we can't test it 
	// directly because of log.Fatalf. This is a design improvement opportunity.
	t.Skip("Cannot test error cases due to log.Fatalf usage - would need refactoring")
}