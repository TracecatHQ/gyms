package tracecat

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMCPIntegration() *schema.Resource {
	return &schema.Resource{
		CreateContext: mcpCreate,
		ReadContext:   mcpRead,
		DeleteContext: jsonDelete("/mcp-integrations"),
		Schema: map[string]*schema.Schema{
			"workspace_id":         workspaceSchema(),
			"catalog_slug":         {Type: schema.TypeString, Required: true, ForceNew: true},
			"connection_option_id": {Type: schema.TypeString, Optional: true, ForceNew: true},
			"name":                 {Type: schema.TypeString, Optional: true, ForceNew: true},
			"description":          {Type: schema.TypeString, Optional: true, ForceNew: true},
			"server_uri":           {Type: schema.TypeString, Optional: true, ForceNew: true},
			"auth_type":            {Type: schema.TypeString, Optional: true, Default: "CUSTOM", ForceNew: true},
			"timeout":              {Type: schema.TypeInt, Optional: true, Default: 120, ForceNew: true},
			"custom_headers_wo_json": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
			},
			"credentials_wo_version": {Type: schema.TypeInt, Optional: true, Default: 0, ForceNew: true},
			"state":                  {Type: schema.TypeString, Computed: true},
		},
	}
}

func mcpCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	serverURI := d.Get("server_uri").(string)
	if serverURI == "" {
		payload := map[string]any{}
		if option := d.Get("connection_option_id").(string); option != "" {
			payload["connection_option_id"] = option
		}
		_, err = c.JSON(ctx, http.MethodPost, "/mcp-integrations/catalog/"+d.Get("catalog_slug").(string)+"/connect", d.Get("workspace_id").(string), payload, &out)
	} else {
		headers := map[string]any{}
		if value, ok := d.GetOk("custom_headers_wo_json"); ok {
			headers, err = decodeObject(value.(string))
			if err != nil {
				return diag.FromErr(err)
			}
		}
		payload := map[string]any{
			"name":               d.Get("name"),
			"description":        d.Get("description"),
			"catalog_slug":       d.Get("catalog_slug"),
			"server_type":        "http",
			"server_uri":         serverURI,
			"auth_type":          d.Get("auth_type"),
			"custom_credentials": canonicalJSON(headers),
			"timeout":            d.Get("timeout"),
		}
		_, err = c.JSON(ctx, http.MethodPost, "/mcp-integrations", d.Get("workspace_id").(string), payload, &out)
	}
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(responseID(out))
	if d.Id() == "" {
		return diag.Errorf("Tracecat MCP connect response omitted integration id")
	}
	return mcpRead(ctx, d, meta)
}

func mcpRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	status, err := c.JSON(ctx, http.MethodGet, "/mcp-integrations/"+d.Id(), d.Get("workspace_id").(string), nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for _, key := range []string{"name", "description", "server_uri", "auth_type", "timeout", "state"} {
		if value, ok := out[key]; ok {
			_ = d.Set(key, value)
		}
	}
	return nil
}
