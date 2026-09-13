package tracecat

import (
	"context"
	"net/http"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceModel() *schema.Resource {
	return &schema.Resource{
		ReadContext: modelRead,
		Schema: map[string]*schema.Schema{
			"workspace_id":   workspaceSchema(),
			"model_provider": {Type: schema.TypeString, Required: true},
			"name":           {Type: schema.TypeString, Required: true},
			"catalog_id":     {Type: schema.TypeString, Computed: true},
		},
	}
}

func modelRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]map[string]any
	_, err = c.JSON(ctx, http.MethodGet, "/agent/models", d.Get("workspace_id").(string), nil, &out)
	if err != nil {
		return diag.FromErr(err)
	}
	provider, name := d.Get("model_provider").(string), d.Get("name").(string)
	keys := make([]string, 0, len(out))
	for key := range out {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		model := out[key]
		if model["provider"] == provider && model["name"] == name {
			id, _ := model["catalog_id"].(string)
			d.SetId(provider + "/" + name)
			_ = d.Set("catalog_id", id)
			return nil
		}
	}
	return diag.Errorf("model %s/%s is not enabled for workspace %s", provider, name, d.Get("workspace_id"))
}
