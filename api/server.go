// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"crypto/sha3"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/moogar0880/problems"
	"github.com/veraison/cmw"
	"github.com/veraison/ratsd/plugin"
	"github.com/veraison/ratsd/proto/compositor"
	ratsdtoken "github.com/veraison/ratsd/ratsd-token"
	ratsdtokenv2 "github.com/veraison/ratsd/ratsd-token-v2"
	"go.uber.org/zap"
)

// Defines missing consts in the API Spec
const (
	ApplicationvndVeraisonCharesJson string = "application/vnd.veraison.chares+json"
	JsonType                         string = "application/json"
	nonceAdjustFunction              string = ratsdtoken.NonceAdjustFunctionShake256
	legacyCharesResponseMediaType    string = `application/eat-ucs+json; eat_profile="tag:github.com,2024:veraison/ratsd"`
	v2CharesResponseMediaType        string = `application/cmw+cbor; cmwct="tag:github.com,2026:veraison/ratsd/v2"`
	legacyCMWCollectionType          string = "tag:github.com,2025:veraison/ratsd/cmw"
)

type Server struct {
	logger  *zap.SugaredLogger
	manager plugin.IManager
	options string
}

type charesResponseFormat int

const (
	charesResponseLegacy charesResponseFormat = iota
	charesResponseV2
)

type charesResponse struct {
	format      charesResponseFormat
	contentType string
}

func responseCodeToHTTP(responseCode uint32) int {
	// Plugin should return 200 on success, 400 for caller input errors, and 500 for everything else.
	switch responseCode {
	case 200:
		return http.StatusOK
	case 400:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func adjustNonce(nonce []byte, size uint32) ([]byte, error) {
	return adjustNonceWithFunction(nonce, size, nonceAdjustFunction)
}

func adjustNonceWithFunction(nonce []byte, size uint32, function string) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("nonce size must be greater than zero")
	}

	adjusted := make([]byte, int(size))
	var h io.ReadWriter
	switch function {
	case ratsdtoken.NonceAdjustFunctionShake128:
		h = sha3.NewSHAKE128()
	case ratsdtoken.NonceAdjustFunctionShake256:
		h = sha3.NewSHAKE256()
	default:
		return nil, fmt.Errorf("unsupported nonce adjustment function %q", function)
	}

	if _, err := h.Write(nonce); err != nil {
		return nil, err
	}
	if _, err := h.Read(adjusted); err != nil {
		return nil, err
	}

	return adjusted, nil
}

func negotiateCharesResponse(accept *string) (charesResponse, error) {
	defaultResponse := charesResponse{
		format:      charesResponseLegacy,
		contentType: legacyCharesResponseMediaType,
	}
	if accept == nil || strings.TrimSpace(*accept) == "" {
		return defaultResponse, nil
	}

	for _, offered := range splitAcceptHeader(*accept) {
		offered = strings.TrimSpace(offered)
		if offered == "*/*" {
			return defaultResponse, nil
		}

		mediaType, params, err := mime.ParseMediaType(offered)
		if err != nil {
			continue
		}

		switch mediaType {
		case "application/eat-ucs+json":
			if params["eat_profile"] == ratsdtoken.LegacyProfile {
				return defaultResponse, nil
			}
		case "application/cmw+cbor":
			if params["cmwct"] == ratsdtokenv2.Profile {
				return charesResponse{
					format:      charesResponseV2,
					contentType: v2CharesResponseMediaType,
				}, nil
			}
		}
	}

	return charesResponse{}, fmt.Errorf(
		"wrong accept type, expect %s or %s (got %s)",
		legacyCharesResponseMediaType,
		v2CharesResponseMediaType,
		*accept,
	)
}

func splitAcceptHeader(accept string) []string {
	values := []string{}
	start := 0
	inQuotes := false
	escaped := false

	for i, r := range accept {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuotes:
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			values = append(values, accept[start:i])
			start = i + 1
		}
	}

	return append(values, accept[start:])
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

	resp, err := negotiateCharesResponse(param.Accept)
	if param.Accept != nil {
		s.logger.Info("request media type: ", *(param.Accept))
	}
	if err != nil {
		p := problems.NewDetailedProblem(http.StatusNotAcceptable, err.Error())
		s.reportProblem(w, p)
		return
	}

	payload, _ := io.ReadAll(r.Body)
	requestFields := make(map[string]json.RawMessage)
	err = json.Unmarshal(payload, &requestFields)
	if err != nil {
		errMsg := "unable to deserialize JSON request body"
		p := &problems.DefaultProblem{
			Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
			Title:  string(InvalidRequest),
			Detail: errMsg,
			Status: http.StatusBadRequest,
		}
		s.reportProblem(w, p)
		return
	}

	rawNonce, hasNonce := requestFields["nonce"]
	if !hasNonce {
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

	var requestNonce string
	if err := json.Unmarshal(rawNonce, &requestNonce); err != nil || len(requestNonce) < 1 {
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
	delete(requestFields, "nonce")

	selectedAttesters := []string{}
	hasSelection := false
	if rawSelection, ok := requestFields["attester-selection"]; ok {
		hasSelection = true
		if err := json.Unmarshal(rawSelection, &selectedAttesters); err != nil {
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
		delete(requestFields, "attester-selection")
	}

	if s.options == "selected" && len(selectedAttesters) == 0 {
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

	nonce, err := base64.RawURLEncoding.DecodeString(requestNonce)
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
	s.logger.Info("request nonce: ", requestNonce)
	s.logger.Info("response media type: ", resp.contentType)

	legacyEvidence := ratsdtoken.NewEvidence()
	v2Evidence := ratsdtokenv2.NewEvidence()
	if resp.format == charesResponseV2 {
		err = v2Evidence.Claims.SetNonce(nonce)
	} else {
		err = legacyEvidence.Claims.SetNonce(nonce)
	}
	if err != nil {
		errMsg := fmt.Errorf("invalid nonce in the request: %w", err).Error()
		p := &problems.DefaultProblem{
			Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
			Title:  string(InvalidRequest),
			Detail: errMsg,
			Status: http.StatusBadRequest,
		}
		s.reportProblem(w, p)
		return
	}

	var collection *cmw.CMW
	if resp.format == charesResponseLegacy {
		collection = cmw.NewCollection(legacyCMWCollectionType)
	}
	pl := s.manager.GetPluginList()
	if len(pl) == 0 {
		errMsg := "no sub-attester available"
		p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
		s.reportProblem(w, p)
		return
	}

	options := requestFields

	getCMW := func(pn string) bool {
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

		var selectedFormat *compositor.Format
		var outputCt string
		selectedFormat = formatOut.Formats[0]
		outputCt = selectedFormat.ContentType
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
						selectedFormat = f
						outputCt = selectedFormat.ContentType
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
		attesterNonce, err := adjustNonce(nonce, selectedFormat.NonceSize)
		if err != nil {
			errMsg := fmt.Sprintf(
				"failed to adjust nonce for attester %s: %s", pn, err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return false
		}

		if resp.format == charesResponseV2 {
			err = v2Evidence.Claims.SetNonceAdjustFn(nonceAdjustFunction)
		} else {
			err = legacyEvidence.Claims.SetNonceAdjustFn(nonceAdjustFunction)
		}
		if err != nil {
			errMsg := fmt.Sprintf("failed to set nonce adjustment function: %s", err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return false
		}

		if resp.format == charesResponseV2 {
			err = v2Evidence.Claims.SetKeyandNonceSz(pn, uint(selectedFormat.NonceSize))
		} else {
			err = legacyEvidence.Claims.SetKeyandNonceSz(pn, uint(selectedFormat.NonceSize))
		}
		if err != nil {
			errMsg := fmt.Sprintf("failed to set nonce adjustment map: %s", err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return false
		}

		in := &compositor.EvidenceIn{
			ContentType: outputCt,
			Nonce:       attesterNonce,
			Options:     params,
		}

		out := attester.GetEvidence(in)
		if !out.Status.Result {
			errMsg := fmt.Sprintf(
				"failed to get attestation report from %s: %s ", pn, out.Status.Error)
			p := problems.NewDetailedProblem(responseCodeToHTTP(out.StatusCode), errMsg)
			s.reportProblem(w, p)
			return false
		}

		if resp.format == charesResponseV2 {
			if err := v2Evidence.SetToken(pn, in.ContentType, out.Evidence, cmw.Evidence); err != nil {
				errMsg := fmt.Sprintf("failed to add evidence from %s: %s", pn, err.Error())
				p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
				s.reportProblem(w, p)
				return false
			}
		} else {
			c := cmw.NewMonad(in.ContentType, out.Evidence)
			collection.AddCollectionItem(pn, c)
		}
		return true
	}

	attestersToQuery := pl
	if hasSelection {
		seen := make(map[string]struct{}, len(selectedAttesters))
		attestersToQuery = make([]string, 0, len(selectedAttesters))
		for _, pn := range selectedAttesters {
			if _, ok := seen[pn]; ok {
				continue
			}
			seen[pn] = struct{}{}
			attestersToQuery = append(attestersToQuery, pn)
		}
	}

	for _, pn := range attestersToQuery {
		if !getCMW(pn) {
			return
		}
	}

	var response []byte
	if resp.format == charesResponseV2 {
		// Token signing is not configured by the API yet, but COSE_Sign1
		// serialization requires a non-empty signature field.
		if err := v2Evidence.SetSignature([]byte{0}); err != nil {
			errMsg := fmt.Sprintf("failed to set RATSD v2 token signature: %s", err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return
		}
		response, err = v2Evidence.MarshalCBOR()
	} else {
		if err := legacyEvidence.Claims.SetCMW(collection); err != nil {
			errMsg := fmt.Sprintf("failed to serialize CMW collection: %s", err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return
		}

		response, err = legacyEvidence.MarshalJSON()
	}
	if err != nil {
		errMsg := fmt.Sprintf("failed to serialize RATSD token: %s", err.Error())
		p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
		s.reportProblem(w, p)
		return
	}

	w.Header().Set("Content-Type", resp.contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(response)
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
		entry := SubAttester{Name: pn, Options: options}
		resp = append(resp, entry)
	}

	w.Header().Set("Content-Type", JsonType)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
