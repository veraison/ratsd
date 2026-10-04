// Copyright 2026 Contributors to the Veraison project.
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
	ratsdtokenv2 "github.com/veraison/ratsd/ratsd-token/v2"
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
	if err := json.NewEncoder(w).Encode(prob); err != nil {
		s.logger.Errorf("failed to write problem response: %v", err)
	}
}

func (s *Server) RatsdChares(w http.ResponseWriter, r *http.Request, param RatsdCharesParams) {
	// Check if content type matches the expectation
	ct := r.Header.Get("Content-Type")
	if ct != ApplicationvndVeraisonCharesJson {
		errMsg := fmt.Sprintf("wrong content type, expect %s (got %s)", ApplicationvndVeraisonCharesJson, ct)
		p := invalidRequestProblem(errMsg)
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

	req, prob := parseCharesRequest(r.Body)
	if prob != nil {
		s.reportProblem(w, prob)
		return
	}
	if s.options == "selected" && len(req.selectedAttesters) == 0 {
		s.reportProblem(w, invalidRequestProblem("attester-selection must contain at least one attester"))
		return
	}
	if prob := req.decodeNonce(); prob != nil {
		s.reportProblem(w, prob)
		return
	}
	nonce := req.nonce
	options := req.options
	s.logger.Info("request nonce: ", req.encodedNonce)
	s.logger.Info("response media type: ", resp.contentType)

	evidence := newCharesEvidence(resp.format)
	if err := evidence.setNonce(nonce); err != nil {
		errMsg := fmt.Errorf("invalid nonce in the request: %w", err).Error()
		p := invalidRequestProblem(errMsg)
		s.reportProblem(w, p)
		return
	}

	if resp.format == charesResponseLegacy {
		evidence.collection, err = cmw.NewCollection(legacyCMWCollectionType)
		if err != nil {
			s.reportProblem(w, problems.NewDetailedProblem(http.StatusInternalServerError, err.Error()))
			return
		}
	}
	pl := s.manager.GetPluginList()
	if len(pl) == 0 {
		errMsg := "no sub-attester available"
		p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
		s.reportProblem(w, p)
		return
	}

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

		selectedFormat, params, prob := selectAttesterFormat(pn, formatOut.Formats, options[pn])
		if prob != nil {
			s.reportProblem(w, prob)
			return false
		}
		outputCt := selectedFormat.ContentType

		s.logger.Info(pn, " output content type: ", outputCt)
		attesterNonce, err := adjustNonce(nonce, selectedFormat.NonceSize)
		if err != nil {
			errMsg := fmt.Sprintf(
				"failed to adjust nonce for attester %s: %s", pn, err.Error())
			p := problems.NewDetailedProblem(http.StatusInternalServerError, errMsg)
			s.reportProblem(w, p)
			return false
		}

		if err := evidence.setAttesterNonceSize(pn, uint(selectedFormat.NonceSize)); err != nil {
			p := problems.NewDetailedProblem(http.StatusInternalServerError, err.Error())
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

		if err := evidence.addEvidence(pn, in.ContentType, out.Evidence); err != nil {
			s.reportProblem(w, problems.NewDetailedProblem(http.StatusInternalServerError, err.Error()))
			return false
		}
		return true
	}

	attestersToQuery := pl
	if req.hasSelection {
		attestersToQuery = uniqueStrings(req.selectedAttesters)
	}

	for _, pn := range attestersToQuery {
		if !getCMW(pn) {
			return
		}
	}

	response, err := evidence.marshal()
	if err != nil {
		p := problems.NewDetailedProblem(http.StatusInternalServerError, err.Error())
		s.reportProblem(w, p)
		return
	}

	w.Header().Set("Content-Type", resp.contentType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		s.logger.Errorf("failed to write response: %v", err)
	}
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
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Errorf("failed to write response: %v", err)
	}
}

type charesRequest struct {
	nonce             []byte
	encodedNonce      string
	selectedAttesters []string
	hasSelection      bool
	// remaining request fields, keyed by attester name
	options map[string]json.RawMessage
}

func invalidRequestProblem(detail string) *problems.DefaultProblem {
	return &problems.DefaultProblem{
		Type:   string(TagGithubCom2024VeraisonratsdErrorInvalidrequest),
		Title:  string(InvalidRequest),
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

func parseCharesRequest(body io.Reader) (*charesRequest, *problems.DefaultProblem) {
	payload, _ := io.ReadAll(body)
	requestFields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(payload, &requestFields); err != nil {
		return nil, invalidRequestProblem("unable to deserialize JSON request body")
	}

	rawNonce, hasNonce := requestFields["nonce"]
	if !hasNonce {
		return nil, invalidRequestProblem("fail to retrieve nonce from the request")
	}

	req := &charesRequest{selectedAttesters: []string{}}
	if err := json.Unmarshal(rawNonce, &req.encodedNonce); err != nil || req.encodedNonce == "" {
		return nil, invalidRequestProblem("fail to retrieve nonce from the request")
	}
	delete(requestFields, "nonce")

	if rawSelection, ok := requestFields["attester-selection"]; ok {
		req.hasSelection = true
		if err := json.Unmarshal(rawSelection, &req.selectedAttesters); err != nil {
			return nil, invalidRequestProblem(fmt.Sprintf(
				"failed to parse attester selection: %s", err.Error()))
		}
		delete(requestFields, "attester-selection")
	}
	req.options = requestFields

	return req, nil
}

func (r *charesRequest) decodeNonce() *problems.DefaultProblem {
	nonce, err := base64.RawURLEncoding.DecodeString(r.encodedNonce)
	if err != nil {
		return invalidRequestProblem(fmt.Sprintf(
			"fail to decode nonce from the request: %s", err.Error()))
	}
	r.nonce = nonce
	return nil
}

func selectAttesterFormat(
	pn string, formats []*compositor.Format, params json.RawMessage,
) (*compositor.Format, json.RawMessage, *problems.DefaultProblem) {
	if params == nil || string(params) == "null" {
		return formats[0], json.RawMessage{}, nil
	}

	attesterOptions := make(map[string]string)
	if err := json.Unmarshal(params, &attesterOptions); err != nil {
		return nil, nil, invalidRequestProblem(fmt.Sprintf(
			"failed to parse options for %s: %v", pn, err))
	}

	desiredCt, ok := attesterOptions["content-type"]
	if !ok {
		return formats[0], params, nil
	}

	for _, f := range formats {
		if f.ContentType == desiredCt {
			return f, params, nil
		}
	}

	return nil, nil, invalidRequestProblem(fmt.Sprintf(
		"%s does not support content type %s", pn, desiredCt))
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

type charesEvidence struct {
	format charesResponseFormat
	legacy *ratsdtoken.Evidence
	v2     *ratsdtokenv2.Evidence
	// only used for legacy tokens
	collection *cmw.CMW
}

func newCharesEvidence(format charesResponseFormat) *charesEvidence {
	return &charesEvidence{
		format: format,
		legacy: ratsdtoken.NewEvidence(),
		v2:     ratsdtokenv2.NewEvidence(),
	}
}

func (e *charesEvidence) setNonce(nonce []byte) error {
	if e.format == charesResponseV2 {
		return e.v2.Claims.SetNonce(nonce)
	}
	return e.legacy.Claims.SetNonce(nonce)
}

func (e *charesEvidence) setAttesterNonceSize(pn string, size uint) error {
	var err error
	if e.format == charesResponseV2 {
		err = e.v2.Claims.SetNonceAdjustFn(nonceAdjustFunction)
	} else {
		err = e.legacy.Claims.SetNonceAdjustFn(nonceAdjustFunction)
	}
	if err != nil {
		return fmt.Errorf("failed to set nonce adjustment function: %w", err)
	}

	if e.format == charesResponseV2 {
		err = e.v2.Claims.SetKeyandNonceSz(pn, size)
	} else {
		err = e.legacy.Claims.SetKeyandNonceSz(pn, size)
	}
	if err != nil {
		return fmt.Errorf("failed to set nonce adjustment map: %w", err)
	}
	return nil
}

func (e *charesEvidence) addEvidence(pn, contentType string, evidence []byte) error {
	if e.format == charesResponseV2 {
		if err := e.v2.SetToken(pn, contentType, evidence, cmw.Evidence); err != nil {
			return fmt.Errorf("failed to add evidence from %s: %w", pn, err)
		}
		return nil
	}

	c, err := cmw.NewMonad(contentType, evidence)
	if err != nil {
		return fmt.Errorf("failed to create evidence from %s: %w", pn, err)
	}
	if err := e.collection.AddCollectionItem(pn, c); err != nil {
		return fmt.Errorf("failed to add evidence from %s: %w", pn, err)
	}
	return nil
}

func (e *charesEvidence) marshal() ([]byte, error) {
	var (
		response []byte
		err      error
	)
	if e.format == charesResponseV2 {
		// Token signing is not configured by the API yet, but COSE_Sign1
		// serialization requires a non-empty signature field.
		if err := e.v2.SetSignature([]byte{0}); err != nil {
			return nil, fmt.Errorf("failed to set RATSD v2 token signature: %w", err)
		}
		response, err = e.v2.MarshalCBOR()
	} else {
		if err := e.legacy.Claims.SetCMW(e.collection); err != nil {
			return nil, fmt.Errorf("failed to serialize CMW collection: %w", err)
		}
		response, err = e.legacy.MarshalJSON()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to serialize RATSD token: %w", err)
	}
	return response, nil
}
