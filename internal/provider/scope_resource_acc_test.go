package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// Acceptance test for upwind_access_scope. Runs real terraform plan/apply
// against a live tenant: requires TF_ACC=1 plus UPWIND_REGION, UPWIND_ORG_ID,
// UPWIND_CLIENT_ID, UPWIND_CLIENT_SECRET in the environment (`make testacc`).
// The shared provider factories and precheck live in provider_test.go.

func TestAccScopeResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_access_scope",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetScope(context.Background(), rs.Primary.ID)
				return err
			}),
		Steps: []resource.TestStep{
			// Step 1: create a scope, verify what comes back.
			{
				Config: testAccScopeConfig("tf-acc-test-scope", "created by acceptance test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_access_scope.test", "name", "tf-acc-test-scope"),
					resource.TestCheckResourceAttr("upwind_access_scope.test", "description", "created by acceptance test"),
					resource.TestCheckResourceAttr("upwind_access_scope.test", "resource_filters.#", "1"),
					resource.TestCheckResourceAttrSet("upwind_access_scope.test", "id"),
					resource.TestCheckResourceAttrSet("upwind_access_scope.test", "create_time"),
				),
			},
			// Step 2: import the scope by id - proves `terraform import` works.
			{
				ResourceName:      "upwind_access_scope.test",
				ImportState:       true,
				ImportStateVerify: true,
				// The POST (create) response omits creator_id, so the just-created
				// state has it empty, while import (a GET) returns it populated.
				// It's read-only server-owned audit data that never affects a plan,
				// so we skip it in the import-vs-create comparison rather than pay an
				// extra GET on every create. Read still populates it on each refresh.
				ImportStateVerifyIgnore: []string{"creator_id"},
			},
			// Step 3: update name + description - proves PATCH and re-read agree.
			{
				Config: testAccScopeConfig("tf-acc-test-scope-renamed", "updated by acceptance test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_access_scope.test", "name", "tf-acc-test-scope-renamed"),
					resource.TestCheckResourceAttr("upwind_access_scope.test", "description", "updated by acceptance test"),
				),
			},
			// NO FILTER-CHANGE STEP. resource_filters cannot be meaningfully changed
			// in this tenant, and each alternative was rejected live:
			//   - a second value: every value must be an account the tenant owns
			//     (400 "Invalid resource values"), and there is only one, so a
			//     two-element set dedupes to one element
			//   - attribute = "cloud_provider": 400, scopes validate the attribute
			//     against an allowlist the spec does not declare
			//   - operator = "eq": 400 on PATCH, the operator enum is narrower than
			//     the spec's free-form string suggests
			// Set-ordering behaviour is covered on threat policy scopes instead,
			// where the API accepts arbitrary account ids.
			// Destroy runs automatically at the end and fails the test if it errors.
		},
	})
}

// testAccScopeConfig renders the HCL under test. The provider block is empty:
// all four credential settings come from the UPWIND_* environment variables.
// The filter targets cloud_account_id. attribute = "cloud_provider" was tried and
// the API answered 400 BadRequest, so scopes validate the attribute name against
// an allowlist the OpenAPI spec does not declare (it types attribute as any
// non-empty string).
//
// The value must be an account the tenant really owns: a live run answered
//
//	400 Invalid resource values [000000000000] for attribute 'cloud_account_id'
//
// for the placeholder that threat policies accept happily. testAccScopeAccountID()
// is therefore a real onboarded account, not a synthetic one.
func testAccScopeConfig(name, description string) string {
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_access_scope" "test" {
  name        = %q
  description = %q

  resource_filters = [
    {
      attribute = "cloud_account_id"
      operator  = "in"
      values    = [%[3]q]
    }
  ]
}
`, name, description, testAccScopeAccountID())
}
