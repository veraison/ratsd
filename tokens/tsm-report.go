package tokens

import (
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
)

const TSMReportMediaType = "application/vnd.veraison.tsm-report+cbor"

type TSMReport struct {
	AuxBlob       []byte           `json:"auxblob,omitempty"`
	OutBlob       []byte           `json:"outblob"`
	Provider      string           `json:"provider"`
	ServiceReport TsmServiceReport `json:"service,omitempty"`
}

type TsmServiceReport struct {
	ManifestBlob    []byte `json:"manifestblob,omitempty"`
	ServiceProvider string `json:"service_provider,omitempty"`
}

func (t *TSMReport) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

func (t *TSMReport) FromJSON(data []byte) error {
	return json.Unmarshal(data, t)
}

func (t *TSMReport) ToCBOR() ([]byte, error) {
	return cbor.Marshal(t)
}

func (t *TSMReport) FromCBOR(data []byte) error {
	return cbor.Unmarshal(data, t)
}
