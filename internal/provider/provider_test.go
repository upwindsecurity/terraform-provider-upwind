package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// testAccProtoV6ProviderFactories registers the provider for acceptance tests.
// Terraform's testing harness uses this map to start the provider in-process so
// real `terraform plan`/`apply` runs can exercise it. Every acceptance test
// (TF_ACC=1) references this; resources are tested through it as they're added.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"upwind": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPreCheck verifies the environment is ready before acceptance tests run
// against a real tenant: all four UPWIND_* credentials must be set.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	// UPWIND_TEST_ACCOUNT_ID is required alongside the credentials: several tests
	// scope against a real cloud account and there is no default to fall back on.
	// Required for the whole suite rather than per-test, since acceptance tests
	// already need a live tenant and one more export is cheaper than threading a
	// second precheck through the config builders.
	for _, v := range []string{
		"UPWIND_REGION", "UPWIND_ORG_ID", "UPWIND_CLIENT_ID", "UPWIND_CLIENT_SECRET",
		"UPWIND_TEST_ACCOUNT_ID",
	} {
		if os.Getenv(v) == "" {
			t.Fatalf("%s must be set for acceptance tests", v)
		}
	}
}

// testAccScopeAccountID is the cloud account the acceptance tests scope against,
// read from UPWIND_TEST_ACCOUNT_ID.
//
// It has to be a real onboarded account in the tenant under test: access scopes
// validate cloud_account_id referentially and answer 400 "Invalid resource
// values [...]" for an account the tenant does not own. Threat policies do not
// validate and would accept any string, but there is no reason to carry two
// values.
//
// There is deliberately no default. This repository is published, so a real
// account number does not belong in it - testAccPreCheck requires the variable
// instead, which also stops the suite from silently scoping at whichever tenant
// a default happened to name.
func testAccScopeAccountID() string {
	return os.Getenv("UPWIND_TEST_ACCOUNT_ID")
}

// testAccClient builds a real API client from the same environment the provider
// reads. CheckDestroy needs its own: the question it asks is whether the object
// survived on the server, and the provider under test is the thing being doubted.
func testAccClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.New(context.Background(), client.Config{
		Region:       os.Getenv("UPWIND_REGION"),
		OrgID:        os.Getenv("UPWIND_ORG_ID"),
		ClientID:     os.Getenv("UPWIND_CLIENT_ID"),
		ClientSecret: os.Getenv("UPWIND_CLIENT_SECRET"),
	})
	if err != nil {
		t.Fatalf("building acceptance-test API client: %v", err)
	}
	return c
}

// testAccCheckDestroyed builds a CheckDestroy that asks the API whether each
// resource of the given type is really gone once terraform destroy has run.
//
// Without this the destroy phase proves only that Delete returned no error. Every
// threat delete goes through a /bulk endpoint that answers 200 for the whole
// batch, so a delete that silently dropped its payload would look identical to a
// successful one. This is the assertion that tells them apart.
func testAccCheckDestroyed(t *testing.T, resourceType string, fetch func(*client.Client, *terraform.ResourceState) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		c := testAccClient(t)
		for name, rs := range s.RootModule().Resources {
			if rs.Type != resourceType {
				continue
			}
			err := fetch(c, rs)
			if err == nil {
				return fmt.Errorf("%s (id %s) still exists after destroy", name, rs.Primary.ID)
			}
			if !client.IsNotFound(err) {
				return fmt.Errorf("checking %s (id %s) after destroy: %w", name, rs.Primary.ID, err)
			}
		}
		return nil
	}
}

// TestProvider_Metadata is a fast unit test (no TF_ACC required). It proves the
// test harness compiles and the provider wiring works end-to-end in-process.
func TestProvider_Metadata(t *testing.T) {
	p := New("test")()

	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)

	if resp.TypeName != "upwind" {
		t.Errorf("expected provider type name %q, got %q", "upwind", resp.TypeName)
	}
}
