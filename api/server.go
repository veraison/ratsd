// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"
)

// Defines missing consts in the API Spec
const (
	ApplicationvndVeraisonCharesJson string = "application/vnd.veraison.chares+json"
)

type Server struct {
	logger *zap.SugaredLogger
}

func NewServer(logger *zap.SugaredLogger) *Server {
	return &Server{
		logger: logger,
	}
}

func (s *Server) returnBadRequest(w http.ResponseWriter, r *http.Request, errMsg string) {
	s.logger.Error(errMsg)
	badRequestError := &BadRequestError{
		Detail: &errMsg,
		Status: N400,
		Title:  InvalidRequest,
		Type:   TagGithubCom2024VeraisonratsdErrorInvalidrequest,
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(badRequestError)
}

func (s *Server) RatsdChares(w http.ResponseWriter, r *http.Request, param RatsdCharesParams) {
	var requestData ChaResRequest

	// Check if content type matches the expectation
	ct := r.Header.Get("Content-Type")
	if ct != ApplicationvndVeraisonCharesJson {
		errMsg := fmt.Sprintf("wrong content type, expect %s (got %s)", ApplicationvndVeraisonCharesJson, ct)
		s.returnBadRequest(w, r, errMsg)
		return
	}

	respCt := fmt.Sprintf(`application/eat+jwt; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	if *(param.Accept) != respCt {
		errMsg := fmt.Sprintf("wrong accept type, expect %s (got %s)", respCt, *(param.Accept))
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte(errMsg))
		return
	}

	payload, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(payload, &requestData)
	if err != nil || len(requestData.Nonce) < 1 {
		errMsg := "fail to retrieve nonce from the request"
		s.returnBadRequest(w, r, errMsg)
		return
	}

	s.logger.Info("request nonce: ", requestData.Nonce)
	s.logger.Info("request media type: ", *(param.Accept))
	w.Header().Set("Content-Type", respCt)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello from ratsd!"))
}
