package tracecat

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestResolveSecretMatchesEnvironment(t *testing.T) {
	t.Parallel()
	c, err := NewClient("http://tracecat.test/api/", "token")
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `[
			{"id":"secret-prod","name":"shared","environment":"production","keys":["TOKEN"]},
			{"id":"secret-default","name":"shared","environment":"default","keys":["TOKEN"]}
		]`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})

	d := schema.TestResourceDataRaw(t, resourceSecret().Schema, map[string]any{
		"workspace_id":    "workspace-1",
		"name":            "shared",
		"environment":     "default",
		"keys_wo_json":    `{"TOKEN":"value"}`,
		"keys_wo_version": 1,
	})
	if err := resolveSecret(context.Background(), c, d); err != nil {
		t.Fatal(err)
	}
	if d.Id() != "secret-default" {
		t.Fatalf("resolved secret %q, want secret-default", d.Id())
	}
}
