package provider

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Acceptance tests for the read-only Configurations data sources. Require TF_ACC=1
// plus the UPWIND_* credentials (`make testacc`).
//
// Like the threat data sources, these read whatever the tenant happens to contain,
// so the checks assert shape rather than specific values: zero findings is a valid
// answer to a filter, and a test demanding data would be flaky rather than useful.
//
// What only a live run can catch here: the endpoint paths, whether the API accepts
// each filter field/operator, and the hyphenated `cloud-account-id` query param.

func TestAccConfigurationFindingsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// A filtered read is the only kind available: findings has no unfiltered
			// list endpoint, so this doubles as proof the search conditions are
			// accepted. Every returned finding must match, which is the filter
			// actually working rather than being ignored.
			{
				Config: `
provider "upwind" {}

data "upwind_configuration_findings" "failing" {
  max_results = 20

  filters = [
    {
      field    = "status"
      operator = "eq"
      value    = ["fail"]
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.upwind_configuration_findings.failing", "findings.#"),
					testAccCheckEveryFindingAttr("data.upwind_configuration_findings.failing", "status", "fail"),
				),
			},
			// A second field proves the filter enum is more than one accepted value,
			// and that `in` works alongside `eq`.
			{
				Config: `
provider "upwind" {}

data "upwind_configuration_findings" "criticals" {
  filters = [
    {
      field    = "severity"
      operator = "in"
      value    = ["critical"]
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.upwind_configuration_findings.criticals", "findings.#"),
					testAccCheckEveryFindingAttr("data.upwind_configuration_findings.criticals", "severity", "critical"),
				),
			},
		},
	})
}

// An empty filter list satisfies the schema's Required (a set-but-empty list), so
// the guard that actually stops it lives in the client. This asserts the
// practitioner gets the actionable message rather than a raw API 400.
func TestAccConfigurationFindingsDataSource_NoFilters(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "upwind" {}

data "upwind_configuration_findings" "none" {
  filters = []
}
`,
				ExpectError: regexp.MustCompile(`(?s)At least one filter is required`),
			},
		},
	})
}

// A missing finding must fail the plan rather than yield an empty object, for the
// same reason as threat stories: a data source has no state to drop, and an empty
// result would hand downstream references empty strings.
func TestAccConfigurationFindingDataSource_NotFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "upwind" {}

data "upwind_configuration_finding" "missing" {
  id = "tf-acc-no-such-finding"
}
`,
				ExpectError: regexp.MustCompile(`(?s)Configuration finding not found`),
			},
		},
	})
}

// An unknown asset kind returns 200 with an empty items array rather than a 404,
// so this also pins that the empty case is mapped onto a clean error.
func TestAccConfigurationAssetExampleDataSource_NotFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "upwind" {}

data "upwind_configuration_asset_example" "missing" {
  asset_kind = "tf_acc_no_such_asset_kind"
}
`,
				ExpectError: regexp.MustCompile(`(?s)No asset example available`),
			},
		},
	})
}

// testAccCheckEveryFindingAttr asserts every returned finding matches the filter,
// treating zero findings as an acceptable answer.
//
// TestCheckTypeSetElemNestedAttrs cannot express this: it requires at least one
// matching element, so it fails on a tenant with no matching findings - a correct
// result for a filter, not a bug. Mirrors testAccCheckEveryStoryHasStatus.
func testAccCheckEveryFindingAttr(addr, attr, want string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[addr]
		if !ok {
			return fmt.Errorf("%s not found in state", addr)
		}
		n, err := strconv.Atoi(rs.Primary.Attributes["findings.#"])
		if err != nil {
			return fmt.Errorf("%s: unreadable findings count: %w", addr, err)
		}
		for i := 0; i < n; i++ {
			key := fmt.Sprintf("findings.%d.%s", i, attr)
			if got := rs.Primary.Attributes[key]; got != want {
				return fmt.Errorf("%s: %s is %q, want %q - the filter did not constrain the result", addr, key, got, want)
			}
		}
		return nil
	}
}
