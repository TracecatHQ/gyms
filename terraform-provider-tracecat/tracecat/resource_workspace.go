package tracecat

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWorkspace() *schema.Resource {
	return &schema.Resource{
		Description:   "A Tracecat workspace. Protect production gym workspaces with lifecycle.prevent_destroy.",
		CreateContext: workspaceCreate,
		ReadContext:   workspaceRead,
		UpdateContext: workspaceUpdate,
		DeleteContext: workspaceDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"name": {Type: schema.TypeString, Required: true},
		},
	}
}

func workspaceCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	_, err = c.JSON(ctx, http.MethodPost, "/workspaces", "", map[string]any{"name": d.Get("name")}, &out)
	if err != nil {
		return diag.FromErr(err)
	}
	id := responseID(out)
	if id == "" {
		return diag.Errorf("Tracecat workspace create response omitted id")
	}
	d.SetId(id)
	return workspaceRead(ctx, d, meta)
}

func workspaceRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	status, err := c.JSON(ctx, http.MethodGet, "/workspaces/"+d.Id(), "", nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	if name, ok := out["name"].(string); ok {
		_ = d.Set("name", name)
	}
	return nil
}

func workspaceUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = c.JSON(ctx, http.MethodPatch, "/workspaces/"+d.Id(), "", map[string]any{"name": d.Get("name")}, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	return workspaceRead(ctx, d, meta)
}

func workspaceDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	status, err := c.JSON(ctx, http.MethodDelete, "/workspaces/"+d.Id(), "", nil, nil)
	if err != nil && status != http.StatusNotFound {
		return diag.FromErr(fmt.Errorf("delete workspace: %w", err))
	}
	d.SetId("")
	return nil
}
