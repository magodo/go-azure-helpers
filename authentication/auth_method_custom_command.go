// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package authentication

import (
	"context"
	"fmt"

	"github.com/Azure/go-autorest/autorest"
	"github.com/hashicorp/go-multierror"
	authWrapper "github.com/manicminer/hamilton-autorest/auth"
	"github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/environments"
)

type customCommandAuth struct {
	// isSP specifies whether this is a SP or a user
	isSP    bool
	command []string

	// Fields from builder
	// required
	subscriptionId string
	tenantId       string
	tenantOnly     bool
	// optional
	environment        string
	auxiliaryTenantIds []string
}

func (a customCommandAuth) build(b Builder) (authMethod, error) {
	auth := customCommandAuth{
		isSP:    b.IsSP,
		command: b.CustomCommand,

		subscriptionId:     b.SubscriptionID,
		tenantId:           b.TenantID,
		tenantOnly:         b.TenantOnly,
		environment:        b.Environment,
		auxiliaryTenantIds: b.AuxiliaryTenantIDs,
	}

	return auth, nil
}

func (a customCommandAuth) isApplicable(b Builder) bool {
	return b.SupportsCustomCommandAuth
}

func (a customCommandAuth) getADALToken(_ context.Context, _ autorest.Sender, oauthConfig *OAuthConfig, endpoint string) (autorest.Authorizer, error) {
	return nil, fmt.Errorf("getADALToken not implemented for custom command auth method")
}

func (a customCommandAuth) getMSALToken(ctx context.Context, api environments.Api, _ autorest.Sender, _ *OAuthConfig, _ string) (autorest.Authorizer, error) {
	config, err := auth.NewCustomCommandConfig(api, a.tenantId, a.auxiliaryTenantIds, "", a.command)
	if err != nil {
		return nil, err
	}
	return &authWrapper.Authorizer{Authorizer: config.TokenSource(ctx)}, nil
}

func (a customCommandAuth) name() string {
	return "Obtaining a token from the custom  command"
}

func (a customCommandAuth) populateConfig(c *Config) error {
	// TODO
	// c.GetAuthenticatedObjectID = func(ctx context.Context) (*string, error) {
	// }

	return nil
}

func (a customCommandAuth) validate() error {
	var err *multierror.Error

	fmtErrorMessage := "A %s must be configured when authenticating via custom command."

	// Validate the required fields
	if len(a.command) == 0 {
		err = multierror.Append(err, fmt.Errorf(fmtErrorMessage, "Commands"))
	}

	// Validate the required fields from builder
	if !a.tenantOnly && a.subscriptionId == "" {
		err = multierror.Append(err, fmt.Errorf(fmtErrorMessage, "Subscription ID"))
	}
	if a.tenantId == "" {
		err = multierror.Append(err, fmt.Errorf(fmtErrorMessage, "Tenant ID"))
	}

	return err.ErrorOrNil()
}
