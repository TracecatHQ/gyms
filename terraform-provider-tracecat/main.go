package main

import (
	"github.com/TracecatHQ/terraform-provider-tracecat/tracecat"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: tracecat.Provider,
		ProviderAddr: "registry.terraform.io/tracecathq/tracecat",
	})
}
