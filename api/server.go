// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/moogar0880/problems"
	"github.com/veraison/ratsd/plugin"
	"github.com/veraison/ratsd/proto/compositor"
	"go.uber.org/zap"
)

// Defines missing consts in the API Spec
const (
	ApplicationvndVeraisonCharesJson string = "application/vnd.veraison.chares+json"
	ExpectedAuth                     string = "Bearer my.jwt.token"
)

type Server struct {
	logger  *zap.SugaredLogger
	manager plugin.IManager
}

func NewServer(logger *zap.SugaredLogger, manager plugin.IManager) *Server {
	return &Server{
		logger:  logger,
		manager: manager,
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

	auth := r.Header.Get("Authorization")
	if auth != ExpectedAuth {
		p := &problems.DefaultProblem{
			Type:   string(TagGithubCom2024VeraisonratsdErrorUnauthorized),
			Title:  string(AccessUnauthorized),
			Detail: "wrong or missing authorization header",
			Status: http.StatusUnauthorized,
		}
		s.reportProblem(w, p)
		return
	}

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

	nonce, err := base64.StdEncoding.DecodeString(requestData.Nonce)
	if err != nil {
		errMsg := fmt.Sprintf("fail to decode nonce from the request: %s", err.Error())
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
	s.logger.Info("request media type: ", *(param.Accept))

	// Use a map until we finalize ratsd output format
	eat := make(map[string]interface{})
	cmw := make(map[string]string)
	eat["eat_profile"] = TagGithubCom2024Veraisonratsd
	eat["eat_nonce"] = requestData.Nonce
	eat["cmw"] = cmw

	for _, pn := range s.manager.GetPluginList() {
		attester, err := s.manager.LookupByName(pn)
		if err != nil {
			errMsg := fmt.Sprintf(
				"failed to get handle from %s: %s", pn, err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return
		}

		formatOut := attester.GetSupportedFormats()
		if formatOut.Status.Result || len(formatOut.Formats) == 0 {
			errMsg := fmt.Sprintf("no supported formats from attester %s: %s ",
				pn, formatOut.Status.Error)
			s.logger.Info(errMsg)
			continue
		}

		s.logger.Info("output content type: ", formatOut.Formats[0].ContentType)
		in := &compositor.EvidenceIn{
			ContentType: formatOut.Formats[0].ContentType,
			Nonce:       nonce,
		}

		out := attester.GetEvidence(in)
		if out.Status.Result {
			errMsg := fmt.Sprintf(
				"failed to get attestation report from %s:%s ", pn, out.Status.Error)
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return
		}

		cmw[pn] = string(out.Evidence)
	}

	w.Header().Set("Content-Type", respCt)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(eat)
}
