package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// Acceptance test for upwind_threat_policy. Runs real terraform plan/apply
// against a live tenant: requires TF_ACC=1 plus UPWIND_REGION, UPWIND_ORG_ID,
// UPWIND_CLIENT_ID, UPWIND_CLIENT_SECRET in the environment (`make testacc`).
// The shared provider factories and precheck live in provider_test.go.

func TestAccThreatPolicyResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_threat_policy",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetThreatPolicy(context.Background(), rs.Primary.ID)
				return err
			}),
		Steps: []resource.TestStep{
			// Step 1: create. Exercises the bulk-create-with-one-element path and
			// confirms the write-side default_severity comes back as severity.
			{
				Config: testAccThreatPolicyConfig("tf-acc-test-policy", "high", "cloud_logs", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "name", "tf-acc-test-policy"),
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "severity", "high"),
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "source_type", "cloud_logs"),
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "is_enabled", "true"),
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "metadata.detection_title", "TF Acc Detection"),
					// Two elements, so the Set round-trip is exercised: the API may return
					// them in either order and state must still compare equal. This lives
					// here rather than on access scopes because threat policies accept
					// arbitrary account ids, and a two-element set needs two of them.
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "resource_scope.condition.value.#", "2"),
					resource.TestCheckTypeSetElemAttr("upwind_threat_policy.test", "resource_scope.condition.value.*", testAccScopeAccountID()),
					resource.TestCheckTypeSetElemAttr("upwind_threat_policy.test", "resource_scope.condition.value.*", "111111111111"),
					resource.TestCheckResourceAttrSet("upwind_threat_policy.test", "id"),
					resource.TestCheckResourceAttrSet("upwind_threat_policy.test", "create_time"),
				),
			},
			// Step 2: import by id - proves `terraform import` works and that a
			// GET-derived state matches a create-derived one.
			{
				ResourceName:      "upwind_threat_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
				// The bulk-create response omits the audit fields that a GET returns,
				// so the just-created state has them empty while import has them
				// populated. They are read-only and never affect a plan, so skip them
				// in the comparison rather than pay an extra GET on every create.
				// create_time/update_time are excluded for the same reason: the API
				// stamps the write response and the stored record at slightly different
				// moments and truncates to whole seconds, so they differ by 1s whenever
				// a create straddles a second boundary. Observed live as
				// 11:08:43 from create vs 11:08:44 from GET. Server-owned audit data
				// that never affects a plan.
				ImportStateVerifyIgnore: []string{"creator_id", "last_modifier_id", "create_time", "update_time"},
			},
			// Step 3: update severity and disable - proves the bulk PATCH path and
			// that the re-read agrees with what was sent.
			{
				Config: testAccThreatPolicyConfig("tf-acc-test-policy-renamed", "critical", "cloud_logs", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "name", "tf-acc-test-policy-renamed"),
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "severity", "critical"),
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "is_enabled", "false"),
				),
			},
			// Step 4: drop resource_scope entirely - proves an omitted block clears
			// the scope on the server instead of silently leaving it in place.
			{
				Config: testAccThreatPolicyConfigNoScope("tf-acc-test-policy-renamed", "critical"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("upwind_threat_policy.test", "resource_scope.condition.type"),
				),
			},
			// Step 5: change source_type - the one field absent from the bulk edit
			// body, so it cannot be updated in place. If RequiresReplace were missing
			// the provider would send a PATCH the API silently ignores, and the
			// policy would report the old source_type forever.
			{
				Config: testAccThreatPolicyConfigSourceType("tf-acc-test-policy-renamed", "critical", "sensor"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("upwind_threat_policy.test", plancheck.ResourceActionReplace),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy.test", "source_type", "sensor"),
				),
			},
			// Destroy runs automatically at the end and fails the test if it errors.
		},
	})
}

// testAccThreatPolicyConfig renders the HCL under test. The provider block is
// empty: all four credential settings come from the UPWIND_* environment
// variables.
//
// The scope uses cloud_account_rule with the testAccScopeAccountID() placeholder.
// cloud_provider_rule would need no id at all, but the API rejects it for policy
// scopes ("condition type(s) not allowed") even though the OpenAPI spec lists it
// among the scope condition types, so an account-based condition is the option
// left.
func testAccThreatPolicyConfig(name, severity, sourceType string, enabled bool) string {
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_threat_policy" "test" {
  name        = %q
  severity    = %q
  source_type = %q
  is_enabled  = %t

  metadata = {
    detection_title       = "TF Acc Detection"
    detection_description = "created by acceptance test"
  }

  resource_scope = {
    condition = {
      type     = "cloud_account_rule"
      field    = "cloud_account_id"
      operator = "in"
      value    = [%q, "111111111111"]
    }
  }
}
`, name, severity, sourceType, enabled, testAccScopeAccountID())
}

// testAccThreatPolicyConfigNoScope is the same policy with resource_scope removed.
func testAccThreatPolicyConfigNoScope(name, severity string) string {
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_threat_policy" "test" {
  name        = %q
  severity    = %q
  source_type = "cloud_logs"
  is_enabled  = false

  metadata = {
    detection_title       = "TF Acc Detection"
    detection_description = "created by acceptance test"
  }
}
`, name, severity)
}

// testAccThreatPolicyConfigSourceType is testAccThreatPolicyConfigNoScope with a
// settable source_type, used to exercise the replacement path.
func testAccThreatPolicyConfigSourceType(name, severity, sourceType string) string {
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_threat_policy" "test" {
  name        = %q
  severity    = %q
  source_type = %q
  is_enabled  = false

  metadata = {
    detection_title       = "TF Acc Detection"
    detection_description = "created by acceptance test"
  }
}
`, name, severity, sourceType)
}
