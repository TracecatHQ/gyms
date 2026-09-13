package tracecat

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	p := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("TRACECAT_API_URL", "http://localhost/api"),
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("TRACECAT_API_KEY", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"tracecat_workspace":       resourceWorkspace(),
			"tracecat_workflow":        resourceWorkflow(),
			"tracecat_agent_preset":    resourceJSON("/agent/presets", false),
			"tracecat_table":           resourceTable(),
			"tracecat_table_row":       resourceTableRow(),
			"tracecat_case_field":      resourceJSON("/case-fields", false),
			"tracecat_case_dropdown":   resourceJSON("/case-dropdowns", false),
			"tracecat_case_tag":        resourceJSON("/case-tags", false),
			"tracecat_mcp_integration": resourceMCPIntegration(),
			"tracecat_secret":          resourceSecret(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"tracecat_model": dataSourceModel(),
		},
	}
	p.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (any, diag.Diagnostics) {
		client, err := NewClient(d.Get("api_url").(string), d.Get("api_key").(string))
		if err != nil {
			return nil, diag.FromErr(err)
		}
		return client, nil
	}
	return p
}

func client(meta any) (*Client, error) {
	c, ok := meta.(*Client)
	if !ok || c == nil {
		return nil, fmt.Errorf("Tracecat provider was not configured")
	}
	return c, nil
}

func workspaceSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
	}
}

func envOrEmpty(name string) string { return os.Getenv(name) }
