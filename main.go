package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/upwindsecurity/terraform-provider-upwind/internal/provider"
)

// version is set at build time via -ldflags by the release pipeline; "dev" locally.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		// The address Terraform uses to find this provider in the registry.
		Address: "registry.terraform.io/upwindsecurity/upwind",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
