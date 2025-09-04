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
	"github.com/veraison/cmw"
	"github.com/veraison/ratsd/plugin"
	"github.com/veraison/ratsd/proto/compositor"
	"go.uber.org/zap"
)

// Defines missing consts in the API Spec
const (
	ApplicationvndVeraisonCharesJson string = "application/vnd.veraison.chares+json"
	JsonType string = "application/json"
)

type Server struct {
	logger  *zap.SugaredLogger
	manager plugin.IManager
	options string
}

func NewServer(logger *zap.SugaredLogger, manager plugin.IManager, options string) *Server {
	return &Server{
		logger:  logger,
		manager: manager,
		options: options,
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

	respCt := fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, TagGithubCom2024Veraisonratsd)
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

	nonce, err := base64.RawURLEncoding.DecodeString(requestData.Nonce)
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
	collection := cmw.NewCollection("tag:github.com,2025:veraison/ratsd/cmw")
	eat["eat_profile"] = TagGithubCom2024Veraisonratsd
	eat["eat_nonce"] = requestData.Nonce
	pl := s.manager.GetPluginList()
	if len(pl) == 0 {
		errMsg := "no sub-attester available"
		p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
		s.reportProblem(w, p)
		return
	}

	var options map[string]json.RawMessage
	if len(requestData.AttesterSelection) > 0 {
		err := json.Unmarshal(requestData.AttesterSelection, &options)
		if err != nil {
			errMsg := fmt.Sprintf(
				"failed to parse attester selection: %s", err.Error())
			p := &problems.DefaultProblem{
				Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
				Title:  string(InvalidRequest),
				Detail: errMsg,
				Status: http.StatusBadRequest,
			}
			s.reportProblem(w, p)
			return
		}
	} else if s.options == "selected" {
		errMsg := "attester-selection must contain at least one attester"
		p := &problems.DefaultProblem{
			Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
			Title:  string(InvalidRequest),
			Detail: errMsg,
			Status: http.StatusBadRequest,
		}
		s.reportProblem(w, p)
		return
	}

	getCMW := func (pn string) bool {
		attester, err := s.manager.LookupByName(pn)
		if err != nil {
			errMsg := fmt.Sprintf(
				"failed to get handle from %s: %s", pn, err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return false
		}

		formatOut := attester.GetSupportedFormats()
		if !formatOut.Status.Result || len(formatOut.Formats) == 0 {
			errMsg := fmt.Sprintf("no supported formats from attester %s: %s ",
				pn, formatOut.Status.Error)
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return false
		}

		outputCt := formatOut.Formats[0].ContentType
		params, hasOption := options[pn]
		if !hasOption || string(params) == "null" {
			params = json.RawMessage{}
		} else {
			attesterOptions := make(map[string]string)
			if err := json.Unmarshal(params, &attesterOptions); err != nil {
				errMsg := fmt.Sprintf(
					"failed to parse options for %s: %v", pn, err)
				p := &problems.DefaultProblem{
					Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
					Title:  string(InvalidRequest),
					Detail: errMsg,
					Status: http.StatusBadRequest,
				}
				s.reportProblem(w, p)
				return false
			}

			validCt := false
			if desiredCt, ok := attesterOptions["content-type"]; ok {
				for _, f := range formatOut.Formats {
					if f.ContentType == desiredCt {
						outputCt = desiredCt
						validCt = true
						break
					}
				}

				if !validCt {
					errMsg := fmt.Sprintf(
						"%s does not support content type %s", pn, desiredCt)
					p := &problems.DefaultProblem{
						Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
						Title:  string(InvalidRequest),
						Detail: errMsg,
						Status: http.StatusBadRequest,
					}
					s.reportProblem(w, p)
					return false
				}
			}
		}

		s.logger.Info(pn, " output content type: ", outputCt)
		in := &compositor.EvidenceIn{
			ContentType: outputCt,
			Nonce:       nonce,
			Options:     params,
		}

		out := attester.GetEvidence(in)
		if !out.Status.Result {
			errMsg := fmt.Sprintf(
				"failed to get attestation report from %s: %s ", pn, out.Status.Error)
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return false
		}

		c := cmw.NewMonad(in.ContentType, out.Evidence)
		collection.AddCollectionItem(pn, c)
		return true
	}

	if s.options == "all" {
		for _, pn := range pl {
			if !getCMW(pn) {
				return
			}
		}
	} else {
		for pn, _ := range options {
			if !getCMW(pn) {
				return
			}
		}
	}

	serialized, err := collection.MarshalJSON()
	if err != nil {
		errMsg := fmt.Sprintf("failed to serialize CMW collection: %s", err.Error())
		p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
		s.reportProblem(w, p)
		return
	}
	eat["cmw"] = serialized
	w.Header().Set("Content-Type", respCt)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(eat)
}

func (s *Server) RatsdSubattesters(w http.ResponseWriter, r *http.Request) {
	resp := []SubAttester{}

	pl := s.manager.GetPluginList()
	for _, pn := range pl {
		options := new([]Option)
		attester, err := s.manager.LookupByName(pn)
		if err != nil {
			errMsg := fmt.Sprintf(
				"failed to get handle from %s: %s", pn, err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return
		}

		for _, o := range attester.GetOptions().Options {
			option := Option{Name: o.Name, DataType: OptionDataType(o.Type)}
			*options = append(*options, option)
		}
		entry := SubAttester{Name: pn, Options: options,}
		resp = append(resp, entry)
	}

	w.Header().Set("Content-Type", JsonType)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
