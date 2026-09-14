package tracecat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientSetsWorkspaceAndAuthorization(t *testing.T) {
	t.Parallel()
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("x-tracecat-role-workspace-id"); got != "ws-1" {
			t.Errorf("workspace header = %q", got)
		}
		if got := r.URL.Query().Get("workspace_id"); got != "ws-1" {
			t.Errorf("workspace query = %q", got)
		}
		var body strings.Builder
		_ = json.NewEncoder(&body).Encode(map[string]string{"id": "item-1"})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body.String())), Header: make(http.Header)}, nil
	})
	c, err := NewClient("http://tracecat.test/api/", "token")
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = transport
	var out map[string]any
	if _, err := c.JSON(context.Background(), http.MethodGet, "/things", "ws-1", nil, &out); err != nil {
		t.Fatal(err)
	}
	if got := responseID(out); got != "item-1" {
		t.Fatalf("id = %q", got)
	}
}

func TestCanonicalSubsetDetectsManagedDrift(t *testing.T) {
	t.Parallel()
	remote := map[string]any{"name": "changed", "server_field": true}
	desired := map[string]any{"name": "wanted", "description": "deleted remotely"}
	got := canonicalSubset(remote, desired)
	if got["name"] != "changed" {
		t.Fatalf("unexpected subset: %#v", got)
	}
	if _, exists := got["description"]; exists {
		t.Fatalf("missing remote key was copied from desired state: %#v", got)
	}
}

func TestProviderSchema(t *testing.T) {
	t.Parallel()
	if err := Provider().InternalValidate(); err != nil {
		t.Fatal(err)
	}
}
