package tracecat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceJSON(endpoint string, forceNew bool) *schema.Resource {
	r := &schema.Resource{
		Description:   "A granular Tracecat REST resource represented by canonical JSON.",
		CreateContext: jsonCreate(endpoint),
		ReadContext:   jsonRead(endpoint),
		UpdateContext: jsonUpdate(endpoint),
		DeleteContext: jsonDelete(endpoint),
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"workspace_id": workspaceSchema(),
			"config_json": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         forceNew,
				DiffSuppressFunc: suppressEquivalentJSON,
			},
		},
	}
	if forceNew {
		r.UpdateContext = nil
	}
	return r
}

func decodeObject(raw string) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, fmt.Errorf("config_json must be a JSON object: %w", err)
	}
	return value, nil
}

func canonicalSubset(remote, desired map[string]any) map[string]any {
	out := make(map[string]any, len(desired))
	for key, desiredValue := range desired {
		if remoteValue, ok := remote[key]; ok {
			out[key] = remoteValue
		} else {
			out[key] = desiredValue
		}
	}
	return out
}

func canonicalJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func suppressEquivalentJSON(_ string, old, new string, _ *schema.ResourceData) bool {
	var a, b any
	if json.Unmarshal([]byte(old), &a) != nil || json.Unmarshal([]byte(new), &b) != nil {
		return false
	}
	return canonicalJSON(a) == canonicalJSON(b)
}

func jsonCreate(endpoint string) schema.CreateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
		c, err := client(meta)
		if err != nil {
			return diag.FromErr(err)
		}
		payload, err := decodeObject(d.Get("config_json").(string))
		if err != nil {
			return diag.FromErr(err)
		}
		var out map[string]any
		_, err = c.JSON(ctx, http.MethodPost, endpoint, d.Get("workspace_id").(string), payload, &out)
		if err != nil {
			return diag.FromErr(err)
		}
		id := responseID(out)
		if id == "" {
			return diag.Errorf("Tracecat %s create response omitted id", endpoint)
		}
		d.SetId(id)
		return jsonRead(endpoint)(ctx, d, meta)
	}
}

func jsonRead(endpoint string) schema.ReadContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
		c, err := client(meta)
		if err != nil {
			return diag.FromErr(err)
		}
		var out map[string]any
		status, err := c.JSON(ctx, http.MethodGet, endpoint+"/"+d.Id(), d.Get("workspace_id").(string), nil, &out)
		if status == http.StatusNotFound {
			d.SetId("")
			return nil
		}
		if err != nil {
			return diag.FromErr(err)
		}
		desired, err := decodeObject(d.Get("config_json").(string))
		if err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("config_json", canonicalJSON(canonicalSubset(out, desired))); err != nil {
			return diag.FromErr(err)
		}
		return nil
	}
}

func jsonUpdate(endpoint string) schema.UpdateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
		c, err := client(meta)
		if err != nil {
			return diag.FromErr(err)
		}
		payload, err := decodeObject(d.Get("config_json").(string))
		if err != nil {
			return diag.FromErr(err)
		}
		_, err = c.JSON(ctx, http.MethodPatch, endpoint+"/"+d.Id(), d.Get("workspace_id").(string), payload, nil)
		if err != nil {
			return diag.FromErr(err)
		}
		return jsonRead(endpoint)(ctx, d, meta)
	}
}

func jsonDelete(endpoint string) schema.DeleteContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
		c, err := client(meta)
		if err != nil {
			return diag.FromErr(err)
		}
		status, err := c.JSON(ctx, http.MethodDelete, endpoint+"/"+d.Id(), d.Get("workspace_id").(string), nil, nil)
		if err != nil && status != http.StatusNotFound {
			return diag.FromErr(err)
		}
		d.SetId("")
		return nil
	}
}

func sortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func endpointID(endpoint, id string) string { return strings.TrimRight(endpoint, "/") + "/" + id }
