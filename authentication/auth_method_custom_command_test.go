// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package authentication

import (
	"reflect"
	"testing"
)

func TestCustomCommandAuth_builder(t *testing.T) {
	builder := Builder{
		CustomCommand:      []string{"foo"},
		IsSP:               true,
		TenantID:           "some-tenant-id",
		AuxiliaryTenantIDs: []string{"id1", "id2"},
	}
	auth, err := customCommandAuth{}.build(builder)
	if err != nil {
		t.Fatalf("Error building custom command auth: %s", err)
	}
	cmdauth := auth.(customCommandAuth)

	if !reflect.DeepEqual(builder.CustomCommand, cmdauth.command) {
		t.Fatalf("Expected custom command to be %v but got %v", builder.CustomCommand, cmdauth.command)
	}
	if builder.IsSP != cmdauth.isSP {
		t.Fatalf("Expected IsSP to be %t but got %t", builder.IsSP, cmdauth.isSP)
	}
	if builder.TenantID != cmdauth.tenantId {
		t.Fatalf("Expected Tenant ID to be %s but got %s", builder.TenantID, cmdauth.tenantId)
	}
	if !reflect.DeepEqual(builder.AuxiliaryTenantIDs, cmdauth.auxiliaryTenantIds) {
		t.Fatalf("Expected Auxiliary IDs to be %v but got %v", builder.AuxiliaryTenantIDs, cmdauth.auxiliaryTenantIds)
	}
}

func TestCustomCommandAuth_isApplicable(t *testing.T) {
	cases := []struct {
		Description string
		Builder     Builder
		Valid       bool
	}{
		{
			Description: "Empty Configuration",
			Builder:     Builder{},
			Valid:       false,
		},
		{
			Description: "Feature Toggled off",
			Builder: Builder{
				SupportsCustomCommandAuth: false,
			},
			Valid: false,
		},
		{
			Description: "Feature Toggled on but no command specified",
			Builder: Builder{
				SupportsCustomCommandAuth: true,
			},
			Valid: false,
		},
		{
			Description: "Command specified but feature toggled off",
			Builder: Builder{
				CustomCommand: []string{"foo"},
			},
			Valid: false,
		},
		{
			Description: "Valid configuration",
			Builder: Builder{
				SupportsCustomCommandAuth: true,
				CustomCommand:             []string{"foo"},
			},
			Valid: true,
		},
	}

	for _, v := range cases {
		applicable := customCommandAuth{}.isApplicable(v.Builder)
		if v.Valid != applicable {
			t.Fatalf("Expected %q to be %t but got %t", v.Description, v.Valid, applicable)
		}
	}
}

func TestCustomCommandAuth_populateConfig(t *testing.T) {
	config := &Config{}
	err := customCommandAuth{isSP: true}.populateConfig(config)
	if err != nil {
		t.Fatalf("Error populating config: %s", err)
	}

	if !config.AuthenticatedAsAServicePrincipal {
		t.Fatalf("Expected `AuthenticatedAsAServicePrincipal` to be true but it wasn't")
	}
}

func TestCustomCommandAuth_validate(t *testing.T) {
	cases := []struct {
		Description string
		Config      customCommandAuth
		ExpectError bool
	}{
		{
			Description: "Empty Configuration",
			Config:      customCommandAuth{},
			ExpectError: true,
		},
		{
			Description: "Missing command",
			Config: customCommandAuth{
				command: nil,
			},
			ExpectError: true,
		},
		{
			Description: "Missing Tenant ID",
			Config: customCommandAuth{
				command: []string{"foo"},
			},
			ExpectError: true,
		},
		{
			Description: "Valid Configuration",
			Config: customCommandAuth{
				command:  []string{"foo"},
				tenantId: "9834f8d0-24b3-41b7-8b8d-c611c461a129",
			},
			ExpectError: false,
		},
	}

	for _, v := range cases {
		err := v.Config.validate()

		if v.ExpectError && err == nil {
			t.Fatalf("Expected an error for %q: didn't get one", v.Description)
		}

		if !v.ExpectError && err != nil {
			t.Fatalf("Expected there to be no error for %q - but got: %v", v.Description, err)
		}
	}
}
