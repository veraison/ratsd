// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"github.com/veraison/ratsd/proto/compositor"
)

// IPluggable respresents a "pluggable" point within Veraison ratsd.
type IPluggable interface {
	// GetEvidence takes *compositor.EvidenceIn as the input, which contains the nonce
	// and one of the content type returned by GetSupportedFormats. It returns a
	// *compositor.EvidenceOut that contains the raw evidence for this subattester as
	// the output.
	GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut

	// GetSubAttesterID returns a *compositor.SubAttesterIDOut that contains
	// the name and the version of the subattesters in field SubAttesterID 
	GetSubAttesterID() *compositor.SubAttesterIDOut

	// GetSupportedFormats returns a *compositor.SupportedFormatsOut that contains
	// a list of the output content type and the input nonce sizes supported by this
	// sub-attester, accessible in field Formats 
	GetSupportedFormats() *compositor.SupportedFormatsOut
}
