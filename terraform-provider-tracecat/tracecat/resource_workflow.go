package tracecat

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWorkflow() *schema.Resource {
	return &schema.Resource{
		CreateContext: workflowCreate,
		ReadContext:   workflowRead,
		DeleteContext: workflowDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"workspace_id": workspaceSchema(),
			"filename":     {Type: schema.TypeString, Required: true, ForceNew: true},
			"yaml":         {Type: schema.TypeString, Required: true, ForceNew: true, Sensitive: true},
			"sha256":       {Type: schema.TypeString, Computed: true},
			"alias":        {Type: schema.TypeString, Required: true, ForceNew: true},
			"title":        {Type: schema.TypeString, Computed: true},
		},
	}
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
	if _, err := c.JSON(ctx, http.MethodPatch, "/workflows/"+d.Id(), d.Get("workspace_id").(string), map[string]any{"status": "online"}, nil); err != nil {
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
	return nil
}

func workflowDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	return jsonDelete("/workflows")(ctx, d, meta)
}
