package tracecat

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSecret() *schema.Resource {
	return &schema.Resource{
		Description:   "A workspace secret. keys_wo_json is write-only and is never stored in plan or state.",
		CreateContext: secretCreate,
		ReadContext:   secretRead,
		UpdateContext: secretUpdate,
		DeleteContext: jsonDelete("/secrets"),
		Schema: map[string]*schema.Schema{
			"workspace_id":    workspaceSchema(),
			"name":            {Type: schema.TypeString, Required: true},
			"description":     {Type: schema.TypeString, Optional: true},
			"environment":     {Type: schema.TypeString, Optional: true, Default: "default"},
			"keys_wo_json":    {Type: schema.TypeString, Required: true, Sensitive: true, WriteOnly: true},
			"keys_wo_version": {Type: schema.TypeInt, Required: true},
			"key_names":       {Type: schema.TypeList, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}},
		},
	}
}

func secretPayload(d *schema.ResourceData) (map[string]any, error) {
	values, err := decodeObject(d.Get("keys_wo_json").(string))
	if err != nil {
		return nil, err
	}
	keys := make([]map[string]any, 0)
	for key, value := range values {
		keys = append(keys, map[string]any{"key": key, "value": value})
	}
	return map[string]any{"type": "custom", "name": d.Get("name"), "description": d.Get("description"), "environment": d.Get("environment"), "keys": keys}, nil
}

func secretCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	payload, err := secretPayload(d)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = c.JSON(ctx, http.MethodPost, "/secrets", d.Get("workspace_id").(string), payload, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := resolveSecret(ctx, c, d); err != nil {
		return diag.FromErr(err)
	}
	if d.Id() == "" {
		return diag.Errorf("created Tracecat secret %q but could not resolve its id", d.Get("name"))
	}
	return secretRead(ctx, d, meta)
}

func secretRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := resolveSecret(ctx, c, d); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resolveSecret(ctx context.Context, c *Client, d *schema.ResourceData) error {
	var out []map[string]any
	_, err := c.JSON(ctx, http.MethodGet, "/secrets", d.Get("workspace_id").(string), nil, &out)
	if err != nil {
		return err
	}
	name := d.Get("name").(string)
	for _, secret := range out {
		if secret["name"] != name {
			continue
		}
		if id := responseID(secret); id != "" {
			d.SetId(id)
		}
		for _, key := range []string{"name", "description", "environment"} {
			if v, ok := secret[key]; ok {
				_ = d.Set(key, v)
			}
		}
		if v, ok := secret["keys"]; ok {
			_ = d.Set("key_names", v)
		}
		return nil
	}
	if d.Id() != "" {
		d.SetId("")
	}
	return nil
}

func secretUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	payload, err := secretPayload(d)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = c.JSON(ctx, http.MethodPost, "/secrets/"+d.Id(), d.Get("workspace_id").(string), payload, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	return secretRead(ctx, d, meta)
}
