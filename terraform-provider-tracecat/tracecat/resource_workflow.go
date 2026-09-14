package tracecat

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWorkflow() *schema.Resource {
	return &schema.Resource{
		CreateContext: workflowCreate,
		ReadContext:   workflowRead,
		UpdateContext: workflowUpdate,
		DeleteContext: workflowDelete,
		Schema: map[string]*schema.Schema{
			"workspace_id":    workspaceSchema(),
			"filename":        {Type: schema.TypeString, Required: true, ForceNew: true},
			"yaml":            {Type: schema.TypeString, Required: true, Sensitive: true},
			"definition_json": {Type: schema.TypeString, Required: true, ForceNew: true, Sensitive: true, DiffSuppressFunc: suppressEquivalentWorkflowDefinition},
			"sha256":          {Type: schema.TypeString, Computed: true},
			"alias":           {Type: schema.TypeString, Required: true, ForceNew: true},
			"title":           {Type: schema.TypeString, Computed: true},
			"status":          {Type: schema.TypeString, Optional: true, Default: "online"},
			"version":         {Type: schema.TypeInt, Computed: true},
		},
	}
}

func suppressEquivalentWorkflowDefinition(_ string, old, new string, _ *schema.ResourceData) bool {
	var remote, desired any
	if json.Unmarshal([]byte(old), &remote) != nil || json.Unmarshal([]byte(new), &desired) != nil {
		return false
	}

	// Tracecat uses entrypoint.ref while importing the graph, then derives the
	// committed entrypoint from that graph and stores only entrypoint.expects.
	if definition, ok := desired.(map[string]any); ok {
		if entrypoint, ok := definition["entrypoint"].(map[string]any); ok {
			delete(entrypoint, "ref")
		}
	}
	return containsDesiredWorkflowJSON(remote, desired, "")
}

func containsDesiredWorkflowJSON(remote, desired any, field string) bool {
	switch desired := desired.(type) {
	case map[string]any:
		remote, ok := remote.(map[string]any)
		if !ok {
			return false
		}
		for key, desiredValue := range desired {
			remoteValue, exists := remote[key]
			if !exists || !containsDesiredWorkflowJSON(remoteValue, desiredValue, key) {
				return false
			}
		}
		return true
	case []any:
		remote, ok := remote.([]any)
		if !ok || len(remote) != len(desired) {
			return false
		}
		if field == "actions" {
			return containsDesiredWorkflowActions(remote, desired)
		}
		if field == "depends_on" {
			return equivalentJSONSet(remote, desired)
		}
		for index, desiredValue := range desired {
			if !containsDesiredWorkflowJSON(remote[index], desiredValue, "") {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(remote, desired)
	}
}

func containsDesiredWorkflowActions(remote, desired []any) bool {
	byRef := make(map[string]any, len(remote))
	for _, action := range remote {
		object, ok := action.(map[string]any)
		if !ok {
			return false
		}
		ref, ok := object["ref"].(string)
		if !ok {
			return false
		}
		byRef[ref] = object
	}
	if len(byRef) != len(remote) {
		return false
	}
	for _, action := range desired {
		object, ok := action.(map[string]any)
		if !ok {
			return false
		}
		ref, ok := object["ref"].(string)
		if !ok || !containsDesiredWorkflowJSON(byRef[ref], object, "") {
			return false
		}
	}
	return true
}

func equivalentJSONSet(a, b []any) bool {
	counts := make(map[string]int, len(a))
	for _, value := range a {
		counts[canonicalJSON(value)]++
	}
	for _, value := range b {
		counts[canonicalJSON(value)]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func workflowCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	raw := []byte(d.Get("yaml").(string))
	var out map[string]any
	if err := c.UploadWorkflow(ctx, d.Get("workspace_id").(string), filepath.Base(d.Get("filename").(string)), raw, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(responseID(out))
	if d.Id() == "" {
		return diag.Errorf("Tracecat workflow create response omitted id")
	}
	_ = d.Set("sha256", fmt.Sprintf("%x", sha256.Sum256(raw)))
	if _, err := c.JSON(ctx, http.MethodPatch, "/workflows/"+d.Id(), d.Get("workspace_id").(string), map[string]any{"alias": d.Get("alias")}, nil); err != nil {
		return diag.FromErr(err)
	}
	var commit map[string]any
	if _, err := c.JSON(ctx, http.MethodPost, "/workflows/"+d.Id()+"/commit", d.Get("workspace_id").(string), map[string]any{}, &commit); err != nil {
		return diag.FromErr(err)
	}
	if commit["status"] != "success" {
		return diag.Errorf("Tracecat rejected workflow %q: %v", d.Get("alias"), commit)
	}
	if _, err := c.JSON(ctx, http.MethodPatch, "/workflows/"+d.Id(), d.Get("workspace_id").(string), map[string]any{"status": d.Get("status")}, nil); err != nil {
		return diag.FromErr(err)
	}
	return workflowRead(ctx, d, meta)
}

func workflowRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	status, err := c.JSON(ctx, http.MethodGet, "/workflows/"+d.Id(), d.Get("workspace_id").(string), nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	if value, ok := out["alias"].(string); ok {
		_ = d.Set("alias", value)
	}
	if value, ok := out["title"].(string); ok {
		_ = d.Set("title", value)
	}
	if value, ok := out["status"].(string); ok {
		_ = d.Set("status", value)
	}
	var definition struct {
		Version int            `json:"version"`
		Content map[string]any `json:"content"`
	}
	if _, err := c.JSON(ctx, http.MethodGet, "/workflows/"+d.Id()+"/definition", d.Get("workspace_id").(string), nil, &definition); err != nil {
		return diag.FromErr(err)
	}
	definitionJSON := canonicalJSON(definition.Content)
	if err := d.Set("definition_json", definitionJSON); err != nil {
		return diag.FromErr(err)
	}
	_ = d.Set("sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(definitionJSON))))
	_ = d.Set("version", definition.Version)
	return nil
}

func workflowUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	if d.HasChange("status") {
		if _, err := c.JSON(ctx, http.MethodPatch, "/workflows/"+d.Id(), d.Get("workspace_id").(string), map[string]any{"status": d.Get("status")}, nil); err != nil {
			return diag.FromErr(err)
		}
	}
	return workflowRead(ctx, d, meta)
}

func workflowDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	return jsonDelete("/workflows")(ctx, d, meta)
}
