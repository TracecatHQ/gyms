package tracecat

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestWorkflowReadUsesCommittedDefinition(t *testing.T) {
	t.Parallel()

	const desiredYAML = "version: 1\ndefinition:\n  title: Candidate Run\n"
	const desiredDefinition = `{"title":"Candidate Run"}`
	d := schema.TestResourceDataRaw(t, resourceWorkflow().Schema, map[string]any{
		"workspace_id":    "ws-1",
		"filename":        "candidate-run.yml",
		"yaml":            desiredYAML,
		"definition_json": desiredDefinition,
		"alias":           "candidate_run",
		"status":          "online",
	})
	d.SetId("wf-1")

	c, err := NewClient("http://tracecat.test/api/", "token")
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"id":"wf-1","alias":"candidate_run","title":"Candidate Run","status":"offline"}`
		if strings.HasSuffix(r.URL.Path, "/definition") {
			body = `{"version":2,"content":{"title":"Changed Run","actions":[]}}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})

	if diags := workflowRead(context.Background(), d, c); diags.HasError() {
		t.Fatal(diags)
	}
	if got := d.Get("yaml").(string); got != desiredYAML {
		t.Fatalf("yaml changed during refresh: %q", got)
	}
	if got := d.Get("definition_json").(string); got != `{"actions":[],"title":"Changed Run"}` {
		t.Fatalf("definition_json = %q", got)
	}
	if got := d.Get("version").(int); got != 2 {
		t.Fatalf("version = %d", got)
	}
	if got := d.Get("status").(string); got != "offline" {
		t.Fatalf("status = %q", got)
	}
}

func TestWorkflowDefinitionComparisonIgnoresTracecatDefaults(t *testing.T) {
	t.Parallel()

	desired := `{"title":"Candidate Run","entrypoint":{"ref":"start","expects":{"case_id":{"type":"str"}}},"actions":[{"ref":"finish","action":"core.transform.reshape","depends_on":["start","middle"],"args":{"value":"ok"}},{"ref":"start","action":"core.transform.reshape","args":{"value":"first"}},{"ref":"middle","action":"core.transform.reshape","args":{"value":"second"}}]}`
	remote := `{"title":"Candidate Run","description":"","entrypoint":{"expects":{"case_id":{"type":"str","enum":null}}},"actions":[{"id":"action-1","ref":"start","action":"core.transform.reshape","args":{"value":"first"},"depends_on":[],"start_delay":0,"join_strategy":"all","mask_output":false},{"id":"action-2","ref":"middle","action":"core.transform.reshape","args":{"value":"second"},"depends_on":[]},{"id":"action-3","ref":"finish","action":"core.transform.reshape","depends_on":["middle","start"],"args":{"value":"ok"}}]}`
	if !suppressEquivalentWorkflowDefinition("", remote, desired, nil) {
		t.Fatal("Tracecat-added defaults caused false drift")
	}

	changed := strings.Replace(desired, `"value":"ok"`, `"value":"changed"`, 1)
	if suppressEquivalentWorkflowDefinition("", remote, changed, nil) {
		t.Fatal("authored workflow change was suppressed")
	}

	changedDependencies := strings.Replace(desired, `["start","middle"]`, `["start"]`, 1)
	if suppressEquivalentWorkflowDefinition("", remote, changedDependencies, nil) {
		t.Fatal("authored dependency change was suppressed")
	}
}
