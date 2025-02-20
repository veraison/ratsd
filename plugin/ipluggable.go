// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

//go:generate mockgen -destination=../api/mocks/ipluggable.go -package=mocks github.com/veraison/ratsd/plugin IPluggable
import (
	"github.com/veraison/ratsd/proto/compositor"
)

// IPluggable respresents a "pluggable" point within Veraison ratsd.
type IPluggable interface {
	GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut

	GetSubAttesterID() *compositor.SubAttesterIDOut

	GetSupportedFormats() *compositor.SupportedFormatsOut
}
