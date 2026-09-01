package provider

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Acceptance tests for the read-only threat data sources. Require TF_ACC=1 plus
// the UPWIND_* credentials (`make testacc`).
//
// These read whatever the tenant happens to contain, so the checks assert shape
// rather than specific values: a tenant with no stories is a valid state, and a
// test that demanded one would be flaky rather than useful.

func TestAccStoriesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Unfiltered read: proves pagination completes and the attribute shape
			// matches the schema.
			{
				Config: `
provider "upwind" {}

data "upwind_threat_stories" "all" {
  max_results = 20
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.upwind_threat_stories.all", "stories.#"),
				),
			},
			// Filtered read: proves the search conditions are accepted by the API.
			// Every returned story must match, which is the filter actually working.
			{
				Config: `
provider "upwind" {}

data "upwind_threat_stories" "open" {
  filters = [
    {
      field    = "status"
      operator = "eq"
      value    = ["OPEN"]
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.upwind_threat_stories.open", "stories.#"),
					testAccCheckEveryStoryHasStatus("data.upwind_threat_stories.open", "OPEN"),
				),
			},
		},
	})
}

func TestAccSkillsDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "upwind" {}

data "upwind_threat_skills" "all" {}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.upwind_threat_skills.all", "skills.#"),
				),
			},
			// threat-policy-manager is a published skill documented in the Upwind
			// docs, so it is a reasonable fixture for the single-skill lookup.
			{
				Config: `
provider "upwind" {}

data "upwind_threat_skill" "policy_manager" {
  name = "threat-policy-manager"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.upwind_threat_skill.policy_manager", "name", "threat-policy-manager"),
					resource.TestCheckResourceAttrSet("data.upwind_threat_skill.policy_manager", "version"),
					resource.TestCheckResourceAttrSet("data.upwind_threat_skill.policy_manager", "description"),
				),
			},
		},
	})
}

// TestAccStoryDataSource_NotFound is the only live coverage the singular story
// data source can get in a tenant with no stories. Stories are emitted by real
// detections and have no create endpoint, so there is nothing to seed.
//
// The negative path is worth pinning on its own: a data source has no state to
// remove, so a missing object must surface as an error. A provider that returned
// an empty story instead would hand downstream references empty strings and fail
// somewhere far from the cause.
//
// The spec puts no format constraint on story-id (minLength 1, nothing else), so
// a fabricated id is a valid request that simply matches nothing.
func TestAccStoryDataSource_NotFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "upwind" {}

data "upwind_threat_story" "missing" {
  id = "tf-acc-no-such-story"
}
`,
				ExpectError: regexp.MustCompile(`(?s)Threat story not found`),
			},
		},
	})
}

// testAccCheckEveryStoryHasStatus asserts that every returned story matches the
// filter, and that zero stories is an acceptable answer.
//
// TestCheckTypeSetElemNestedAttrs cannot express this: it requires at least one
// matching element, so it fails on a tenant with no stories - which is a correct
// result for a filter, not a bug. A test that demands data the tenant may not
// have is a flaky test, and this one failed on exactly that.
func testAccCheckEveryStoryHasStatus(addr, want string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[addr]
		if !ok {
			return fmt.Errorf("%s not found in state", addr)
		}
		n, err := strconv.Atoi(rs.Primary.Attributes["stories.#"])
		if err != nil {
			return fmt.Errorf("%s: unreadable stories count: %w", addr, err)
		}
		for i := 0; i < n; i++ {
			key := fmt.Sprintf("stories.%d.status", i)
			if got := rs.Primary.Attributes[key]; got != want {
				return fmt.Errorf("%s: %s is %q, want %q - the filter did not constrain the result", addr, key, got, want)
			}
		}
		return nil
	}
}
