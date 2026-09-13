package tracecat

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceTableRow() *schema.Resource {
	return &schema.Resource{
		CreateContext: tableRowCreate,
		ReadContext:   tableRowRead,
		UpdateContext: tableRowUpdate,
		DeleteContext: tableRowDelete,
		Schema: map[string]*schema.Schema{
			"workspace_id": workspaceSchema(),
			"table_id":     {Type: schema.TypeString, Required: true, ForceNew: true},
			"data_json":    {Type: schema.TypeString, Required: true, DiffSuppressFunc: suppressEquivalentJSON},
			"upsert":       {Type: schema.TypeBool, Optional: true, Default: false},
			"identity_column": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Stable unique column used to resolve the row after Tracecat's bodyless create response.",
			},
			"identity_value": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "String value of identity_column.",
			},
		},
	}
}

func rowPath(d *schema.ResourceData) string { return "/tables/" + d.Get("table_id").(string) + "/rows" }

func tableRowCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	payload, err := decodeObject(d.Get("data_json").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = c.JSON(ctx, http.MethodPost, rowPath(d), d.Get("workspace_id").(string), map[string]any{"data": payload, "upsert": d.Get("upsert")}, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := resolveTableRowID(ctx, c, d); err != nil {
		return diag.FromErr(err)
	}
	return tableRowRead(ctx, d, meta)
}

func resolveTableRowID(ctx context.Context, c *Client, d *schema.ResourceData) error {
	var out struct {
		Items []map[string]any `json:"items"`
	}
	path := rowPath(d) + "?limit=1000&order_by=" + url.QueryEscape(d.Get("identity_column").(string)) + "&sort=asc"
	_, err := c.JSON(ctx, http.MethodGet, path, d.Get("workspace_id").(string), nil, &out)
	if err != nil {
		return err
	}
	column := d.Get("identity_column").(string)
	value := d.Get("identity_value").(string)
	for _, row := range out.Items {
		if fmt.Sprint(row[column]) == value {
			if id := responseID(row); id != "" {
				d.SetId(id)
				return nil
			}
		}
	}
	return fmt.Errorf("created Tracecat table row but could not resolve %s=%q", column, value)
}

func tableRowRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	status, err := c.JSON(ctx, http.MethodGet, rowPath(d)+"/"+d.Id(), d.Get("workspace_id").(string), nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	desired, err := decodeObject(d.Get("data_json").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	_ = d.Set("data_json", canonicalJSON(canonicalSubset(out, desired)))
	return nil
}

func tableRowUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	payload, err := decodeObject(d.Get("data_json").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = c.JSON(ctx, http.MethodPatch, rowPath(d)+"/"+d.Id(), d.Get("workspace_id").(string), map[string]any{"data": payload}, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	return tableRowRead(ctx, d, meta)
}

func tableRowDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	status, err := c.JSON(ctx, http.MethodDelete, rowPath(d)+"/"+d.Id(), d.Get("workspace_id").(string), nil, nil)
	if err != nil && status != http.StatusNotFound {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
