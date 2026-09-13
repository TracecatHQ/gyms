package tracecat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceTable() *schema.Resource {
	return &schema.Resource{
		CreateContext: tableCreate,
		ReadContext:   tableRead,
		UpdateContext: tableUpdate,
		DeleteContext: tableDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"workspace_id": workspaceSchema(),
			"name":         {Type: schema.TypeString, Required: true},
			"columns_json": {Type: schema.TypeString, Required: true, ForceNew: true, DiffSuppressFunc: suppressEquivalentJSON},
		},
	}
}

func tableCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var columns []map[string]any
	if err := json.Unmarshal([]byte(d.Get("columns_json").(string)), &columns); err != nil {
		return diag.Errorf("columns_json must be an array: %v", err)
	}
	createColumns := make([]map[string]any, 0, len(columns))
	for _, column := range columns {
		created := make(map[string]any, len(column))
		for key, value := range column {
			if key != "is_index" {
				created[key] = value
			}
		}
		createColumns = append(createColumns, created)
	}
	workspaceID := d.Get("workspace_id").(string)
	_, err = c.JSON(ctx, http.MethodPost, "/tables", workspaceID, map[string]any{"name": d.Get("name"), "columns": createColumns}, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	var tables []map[string]any
	_, err = c.JSON(ctx, http.MethodGet, "/tables", workspaceID, nil, &tables)
	if err != nil {
		return diag.FromErr(err)
	}
	for _, table := range tables {
		if table["name"] == d.Get("name") {
			d.SetId(responseID(table))
			break
		}
	}
	if d.Id() == "" {
		return diag.Errorf("created table %q but could not resolve its id", d.Get("name"))
	}
	if err := createTableIndexes(ctx, c, d, columns); err != nil {
		return diag.FromErr(err)
	}
	return tableRead(ctx, d, meta)
}

func createTableIndexes(ctx context.Context, c *Client, d *schema.ResourceData, desired []map[string]any) error {
	var table map[string]any
	if _, err := c.JSON(ctx, http.MethodGet, "/tables/"+d.Id(), d.Get("workspace_id").(string), nil, &table); err != nil {
		return err
	}
	columns, _ := table["columns"].([]any)
	for _, wanted := range desired {
		indexed, _ := wanted["is_index"].(bool)
		if !indexed {
			continue
		}
		name, _ := wanted["name"].(string)
		columnID := ""
		for _, raw := range columns {
			column, ok := raw.(map[string]any)
			if ok && column["name"] == name {
				columnID = responseID(column)
				break
			}
		}
		if columnID == "" {
			return fmt.Errorf("created table %q but could not resolve indexed column %q", d.Get("name"), name)
		}
		if _, err := c.JSON(ctx, http.MethodPatch, "/tables/"+d.Id()+"/columns/"+columnID, d.Get("workspace_id").(string), map[string]any{"is_index": true}, nil); err != nil {
			return err
		}
	}
	return nil
}

func tableRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	status, err := c.JSON(ctx, http.MethodGet, "/tables/"+d.Id(), d.Get("workspace_id").(string), nil, &out)
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
	if columns, ok := out["columns"].([]any); ok {
		var desired []map[string]any
		if err := json.Unmarshal([]byte(d.Get("columns_json").(string)), &desired); err != nil {
			return diag.FromErr(err)
		}
		var normalized []map[string]any
		for _, wanted := range desired {
			for _, raw := range columns {
				column, ok := raw.(map[string]any)
				if !ok || column["name"] != wanted["name"] {
					continue
				}
				normalized = append(normalized, canonicalSubset(column, wanted))
				break
			}
		}
		_ = d.Set("columns_json", canonicalJSON(normalized))
	}
	return nil
}

func tableUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	c, err := client(meta)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = c.JSON(ctx, http.MethodPatch, "/tables/"+d.Id(), d.Get("workspace_id").(string), map[string]any{"name": d.Get("name")}, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	return tableRead(ctx, d, meta)
}

func tableDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	return jsonDelete("/tables")(ctx, d, meta)
}
