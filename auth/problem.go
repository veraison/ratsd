// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"encoding/json"
	"net/http"

	"github.com/moogar0880/problems"
	"github.com/veraison/ratsd/api"
	"go.uber.org/zap"
)

func ReportProblem(logger *zap.SugaredLogger, w http.ResponseWriter, detail string) {
	p := &problems.DefaultProblem{
		Type:   string(api.TagGithubCom2024VeraisonratsdErrorUnauthorized),
		Title:  string(api.AccessUnauthorized),
		Detail: detail,
		Status: http.StatusUnauthorized,
	}

	w.Header().Set("Content-Type", problems.ProblemMediaType)
	w.WriteHeader(p.ProblemStatus())
	json.NewEncoder(w).Encode(p)
}
