// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tokens

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

var provider = "sev_guest"
var serviceProvider = "svsm"
var outblob = []byte{117, 24, 74, 133, 21, 198, 189, 177, 81, 18, 129, 84}
var auxblob = []byte{120, 112, 34, 102, 228, 162, 111, 217, 232, 169, 167, 213, 197, 209, 94, 121, 161, 231, 170, 64}
var manifestblob = []byte{170, 13, 189, 115, 132, 249, 168, 13, 253, 229, 76, 198}

func Test_TSMReport_Valid_Pass(t *testing.T) {
	report := &TSMReport{
		Provider:        provider,
		OutBlob:         outblob,
		AuxBlob:         auxblob,
		ServiceProvider: &serviceProvider,
		ManifestBlob:    manifestblob,
	}

	assert.NoError(t, report.Valid())
}

func Test_TSMReport_Valid_Fail_ManifestBlob(t *testing.T) {
	report := &TSMReport{
		Provider:     provider,
		OutBlob:      outblob,
		AuxBlob:      auxblob,
		ManifestBlob: manifestblob,
	}

	assert.EqualError(t, report.Valid(), `stray field "manifestblob"`)
}

func Test_TSMReport_Valid_Fail_MandatoryField(t *testing.T) {
	report := &TSMReport{
		OutBlob: outblob,
		AuxBlob: auxblob,
	}

	assert.EqualError(t, report.Valid(), `missing mandatory field "provider"`)
}

func Test_TSMReport_JSON_SerDes_Pass(t *testing.T) {
	report := &TSMReport{
		Provider: provider,
		OutBlob:  outblob,
		AuxBlob:  auxblob,
	}

	encodedJson, err := report.ToJSON()
	assert.NoError(t, err)

	decodedReport := &TSMReport{}
	assert.NoError(t, decodedReport.FromJSON(encodedJson))

	assert.True(t, reflect.DeepEqual(report, decodedReport))
}

func Test_TSMReport_CBOR_SerDes_Pass(t *testing.T) {
	report := &TSMReport{
		Provider: provider,
		OutBlob:  outblob,
		AuxBlob:  auxblob,
	}

	encodedCbor, err := report.ToCBOR()
	assert.NoError(t, err)

	decodedReport := &TSMReport{}
	assert.NoError(t, decodedReport.FromCBOR(encodedCbor))

	assert.True(t, reflect.DeepEqual(report, decodedReport))
}
