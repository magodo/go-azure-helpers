package authentication

import (
	"context"
	"testing"

	"github.com/manicminer/hamilton/environments"
	"golang.org/x/oauth2"
)

func TestCustomCommandAuthorizer(t *testing.T) {
	ctx := context.Background()
	cmds := [][]string{
		{"az", "account", "get-access-token", "--resource={{.Endpoint}}"},
		{"echo", "mytoken"},
	}
	for _, cmd := range cmds {
		testCustomCommandAuthorizer(ctx, t, cmd)
	}
}

func testCustomCommandAuthorizer(ctx context.Context, t *testing.T, cmd []string) (token *oauth2.Token) {
	env, err := environments.EnvironmentFromString("public")
	if err != nil {
		t.Fatal(err)
	}

	config, err := NewCustomCommandConfig(env.MsGraph, "", nil, "", cmd)
	if err != nil {
		t.Fatal(err)
	}
	auth := config.TokenSource(ctx)

	token, err = auth.Token()
	if err != nil {
		t.Fatalf("auth.Token(): %v", err)
	}
	if token == nil {
		t.Fatalf("token was nil")
	}
	if token.AccessToken == "" {
		t.Fatalf("token.AccessToken was empty")
	}

	return
}
