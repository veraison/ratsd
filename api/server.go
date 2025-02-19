// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/moogar0880/problems"
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

func (s *Server) reportProblem(w http.ResponseWriter, prob *problems.DefaultProblem) {
	s.logger.Error(prob.Detail)
	w.Header().Set("Content-Type", problems.ProblemMediaType)
	w.WriteHeader(prob.ProblemStatus())
	json.NewEncoder(w).Encode(prob)
}

func (s *Server) RatsdChares(w http.ResponseWriter, r *http.Request, param RatsdCharesParams) {
	var requestData ChaResRequest

	// Check if content type matches the expectation
	ct := r.Header.Get("Content-Type")
	if ct != ApplicationvndVeraisonCharesJson {
		errMsg := fmt.Sprintf("wrong content type, expect %s (got %s)", ApplicationvndVeraisonCharesJson, ct)
		p := &problems.DefaultProblem{
			Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
			Title:  string(InvalidRequest),
			Detail: errMsg,
			Status: http.StatusBadRequest,
		}
		s.reportProblem(w, p)
		return
	}

	respCt := fmt.Sprintf(`application/eat+jwt; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
	if param.Accept != nil {
		s.logger.Info("request media type: ", *(param.Accept))
		if *(param.Accept) != respCt && *(param.Accept) != "*/*" {
			errMsg := fmt.Sprintf(
				"wrong accept type, expect %s (got %s)", respCt, *(param.Accept))
			p := problems.NewDetailedProblem(http.StatusNotAcceptable, errMsg)
			s.reportProblem(w, p)
			return
		}
	}

	payload, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(payload, &requestData)
	if err != nil || len(requestData.Nonce) < 1 {
		errMsg := "fail to retrieve nonce from the request"
		p := &problems.DefaultProblem{
			Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
			Title:  string(InvalidRequest),
			Detail: errMsg,
			Status: http.StatusBadRequest,
		}
		s.reportProblem(w, p)
		return
	}

	s.logger.Info("request nonce: ", requestData.Nonce)
	w.Header().Set("Content-Type", respCt)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello from ratsd!"))
}
