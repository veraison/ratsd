// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package ratsdtokenv2

import (
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

var (
	encMode       cbor.EncMode
	decMode       cbor.DecMode
	claimsEncMode cbor.EncMode
	claimsDecMode cbor.DecMode
)

func init() {
	var err error

	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("CBOR encoder initialization failed: %v", err))
	}

	decMode, err = cbor.DecOptions{}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("CBOR decoder initialization failed: %v", err))
	}

	claimsTagSet := newClaimsTagSet()
	claimsEncMode, err = cbor.CoreDetEncOptions().EncModeWithTags(claimsTagSet)
	if err != nil {
		panic(fmt.Sprintf("CBOR claims encoder initialization failed: %v", err))
	}

	claimsDecMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecModeWithTags(claimsTagSet)
	if err != nil {
		panic(fmt.Sprintf("CBOR claims decoder initialization failed: %v", err))
	}
}

func newClaimsTagSet() cbor.TagSet {
	tags := cbor.NewTagSet()
	if err := tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(claimsCBOR{}),
		claimsTagNumber,
	); err != nil {
		panic(fmt.Sprintf("CBOR claims tag set initialization failed: %v", err))
	}

	return tags
}
