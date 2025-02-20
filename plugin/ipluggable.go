// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"github.com/veraison/ratsd/proto/compositor"
)

// IPluggable respresents a "pluggable" point within Veraison ratsd.
type IPluggable interface {
	GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut

	GetSubAttesterID() *compositor.SubAttesterIDOut

	GetSupportedFormats() *compositor.SupportedFormatsOut
}
