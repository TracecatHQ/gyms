package tracecat

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestWorkflowReadRefreshesPlatformFields(t *testing.T) {
	t.Parallel()

	const desiredYAML = "version: 1\ndefinition:\n  title: Candidate Run\n"
	d := schema.TestResourceDataRaw(t, resourceWorkflow().Schema, map[string]any{
		"workspace_id": "ws-1",
		"filename":     "candidate-run.yml",
		"yaml":         desiredYAML,
		"alias":        "candidate_run",
		"status":       "online",
	})
	d.SetId("wf-1")

	c, err := NewClient("http://tracecat.test/api/", "token")
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"id":"wf-1","alias":"candidate_run","title":"Candidate Run","status":"offline","version":2}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})

	if diags := workflowRead(context.Background(), d, c); diags.HasError() {
		t.Fatal(diags)
	}
	if got := d.Get("yaml").(string); got != desiredYAML {
		t.Fatalf("yaml changed during refresh: %q", got)
	}
	if got := d.Get("version").(int); got != 2 {
		t.Fatalf("version = %d", got)
	}
	if got := d.Get("status").(string); got != "offline" {
		t.Fatalf("status = %q", got)
	}
}

func TestWorkflowYAMLChangesReplaceResource(t *testing.T) {
	t.Parallel()

	if !resourceWorkflow().Schema["yaml"].ForceNew {
		t.Fatal("workflow YAML must replace the resource")
	}
}
