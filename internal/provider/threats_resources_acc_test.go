package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// Acceptance tests for the threat resources. Each runs real terraform plan/apply
// against a live tenant: requires TF_ACC=1 plus UPWIND_REGION, UPWIND_ORG_ID,
// UPWIND_CLIENT_ID, UPWIND_CLIENT_SECRET in the environment (`make testacc`).
// The shared provider factories and precheck live in provider_test.go.

func TestAccRuleDefinitionResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_threat_rule_definition",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetRuleDefinition(context.Background(), rs.Primary.ID)
				return err
			}),
		Steps: []resource.TestStep{
			// Step 1: create with the optional MITRE metadata left unset - proves
			// unset optionals stay null instead of reading back as "".
			{
				Config: testAccRuleDefinitionConfig("tf-acc-test-rd", "", "cloud_trail_logs"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_rule_definition.test", "name", "tf-acc-test-rd"),
					resource.TestCheckResourceAttr("upwind_threat_rule_definition.test", "engine", "rego"),
					resource.TestCheckResourceAttr("upwind_threat_rule_definition.test", "threat_category", "cloud_trail_logs"),
					resource.TestCheckNoResourceAttr("upwind_threat_rule_definition.test", "metadata.mitre_tactic_code"),
					resource.TestCheckResourceAttrSet("upwind_threat_rule_definition.test", "id"),
				),
			},
			{
				ResourceName:      "upwind_threat_rule_definition.test",
				ImportState:       true,
				ImportStateVerify: true,
				// create_time/update_time are excluded for the same reason: the API
				// stamps the write response and the stored record at slightly different
				// moments and truncates to whole seconds, so they differ by 1s whenever
				// a create straddles a second boundary. Observed live as
				// 11:08:43 from create vs 11:08:44 from GET. Server-owned audit data
				// that never affects a plan.
				ImportStateVerifyIgnore: []string{"creator_id", "last_modifier_id", "create_time", "update_time"},
			},
			// Step 2: add MITRE metadata - proves PATCH carries nested metadata.
			{
				Config: testAccRuleDefinitionConfig("tf-acc-test-rd-renamed", "TA0001", "cloud_trail_logs"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_rule_definition.test", "name", "tf-acc-test-rd-renamed"),
					resource.TestCheckResourceAttr("upwind_threat_rule_definition.test", "metadata.mitre_tactic_code", "TA0001"),
				),
			},
			// Step 3: change threat_category - absent from the bulk edit body, so it
			// must force replacement rather than a PATCH the API ignores.
			{
				Config: testAccRuleDefinitionConfig("tf-acc-test-rd-renamed", "TA0001", "process_execution"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("upwind_threat_rule_definition.test", plancheck.ResourceActionReplace),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_rule_definition.test", "threat_category", "process_execution"),
				),
			},
		},
	})
}

// TestAccPolicyRuleResource covers the attachment of a rule definition to a
// policy, including the inherited-vs-owned severity and scope distinction that
// is this resource's main drift hazard.
func TestAccPolicyRuleResource(t *testing.T) {
	// Captured in step 3 and compared in step 4: removing the severity override has
	// to replace the rule, and a new id is the only observable proof it did.
	var idBeforeSeverityRemoval string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_threat_policy_rule",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetPolicyRule(context.Background(), rs.Primary.Attributes["policy_id"], rs.Primary.ID)
				return err
			}),
		Steps: []resource.TestStep{
			// Step 1: attach with no severity or scope override. The API reports the
			// policy's values as effective; state must record neither, or every
			// subsequent plan shows drift.
			{
				Config: testAccPolicyRuleConfig("", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("upwind_threat_policy_rule.test", "id"),
					resource.TestCheckResourceAttrPair(
						"upwind_threat_policy_rule.test", "policy_id",
						"upwind_threat_policy.test", "id"),
					resource.TestCheckNoResourceAttr("upwind_threat_policy_rule.test", "severity"),
					resource.TestCheckNoResourceAttr("upwind_threat_policy_rule.test", "scope.condition.type"),
					// A GET reports the inherited scope as policy_scope. The bulk write
					// response leaves this field empty, which is why Create and Update
					// read the rule back rather than trusting what they were handed.
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "scope_type", "policy_scope"),
				),
			},
			// Step 2: set a severity override - proves the owned value is recorded
			// and that scope_type flips away from policy_scope only for scope.
			{
				Config: testAccPolicyRuleConfig("low", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "severity", "low"),
					// Severity is owned now, scope still is not.
					resource.TestCheckNoResourceAttr("upwind_threat_policy_rule.test", "scope.condition.type"),
				),
			},
			// Step 3: add a scope override naming a different account than the
			// policy's. The rule now owns the scope, so state must record it and
			// scope_type must stop reporting policy_scope.
			{
				Config: testAccPolicyRuleConfig("low", testAccPolicyRuleScopeOverride),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "scope.condition.type", "cloud_account_rule"),
					resource.TestCheckTypeSetElemAttr("upwind_threat_policy_rule.test", "scope.condition.value.*", "111111111111"),
					func(s *terraform.State) error {
						rs := s.RootModule().Resources["upwind_threat_policy_rule.test"]
						// Inherited reads back as policy_scope (step 1); an owned one must not.
						if got := rs.Primary.Attributes["scope_type"]; got == "" || got == "policy_scope" {
							return fmt.Errorf("scope_type is %q after a rule-level scope was set; the rule owns the scope but state reports it as inherited", got)
						}
						idBeforeSeverityRemoval = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 4: remove both overrides. This is the direction drift actually
			// shows up: the API keeps returning EFFECTIVE values inherited from the
			// policy, and a provider that recorded them would report a permanent
			// diff against a config that sets neither.
			//
			// The two removals take different paths. Scope clears in place, which the
			// API supports. Severity cannot: ApiEditPolicyRuleItem accepts only the four
			// enum values, so dropping the override replaces the rule. State reporting
			// no severity is therefore not enough on its own -- a provider that just
			// omitted the field from the PATCH would pass this check while the override
			// stayed live on the server. Assert the id changed, which is the observable
			// difference between clearing it and silently keeping it.
			{
				Config: testAccPolicyRuleConfig("", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("upwind_threat_policy_rule.test", "severity"),
					resource.TestCheckNoResourceAttr("upwind_threat_policy_rule.test", "scope.condition.type"),
					func(s *terraform.State) error {
						got := s.RootModule().Resources["upwind_threat_policy_rule.test"].Primary.ID
						if got == idBeforeSeverityRemoval {
							return fmt.Errorf("policy rule id is still %q after the severity override was removed; the rule was patched in place, which the API cannot use to clear an override, so it is still live on the server", got)
						}
						return nil
					},
				),
			},
			// Step 5: import with the composite "<policy-id>/<policy-rule-id>" address.
			{
				ResourceName:      "upwind_threat_policy_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccPolicyRuleImportID("upwind_threat_policy_rule.test"),
				// create_time/update_time are excluded for the same reason: the API
				// stamps the write response and the stored record at slightly different
				// moments and truncates to whole seconds, so they differ by 1s whenever
				// a create straddles a second boundary. Observed live as
				// 11:08:43 from create vs 11:08:44 from GET. Server-owned audit data
				// that never affects a plan.
				ImportStateVerifyIgnore: []string{"creator_id", "last_modifier_id", "create_time", "update_time"},
			},
		},
	})
}

// TestAccPolicyRuleResource_DisabledParent covers the case TestAccPolicyRuleResource
// structurally cannot: its fixture omits is_enabled on the policy, so the parent is
// always enabled and an inherited-disabled rule never occurs.
//
// The API reports is_enabled as an EFFECTIVE value capped by the policy's, so a rule
// inside a disabled policy reads back false however it was written. With a static
// schema default this planned true and apply contradicted its own plan - "Provider
// produced inconsistent result after apply" - for every rule attached to a disabled
// policy. Staging a policy disabled, attaching rules, then enabling it is a normal
// workflow for a security control, which is why this is not an edge case.
func TestAccPolicyRuleResource_DisabledParent(t *testing.T) {
	// Captured in step 4, compared in step 5: removing is_enabled must reset the rule
	// IN PLACE, so the id has to survive.
	var idBeforeIsEnabledRemoval string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_threat_policy_rule",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetPolicyRule(context.Background(), rs.Primary.Attributes["policy_id"], rs.Primary.ID)
				return err
			}),
		Steps: []resource.TestStep{
			// Step 1: attach to a DISABLED policy. The rule must come back disabled.
			// Before the fix this step failed the apply outright rather than failing
			// an assertion, which is what made the bug invisible to a suite that
			// never built this shape.
			{
				Config: testAccPolicyRuleDisabledParentConfig(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy.parent", "is_enabled", "false"),
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "is_enabled", "false"),
				),
			},
			// Step 2: enable the policy. Only the POLICY can be asserted here.
			//
			// The rule's is_enabled is an effective value the platform recomputes when
			// its parent changes, but the rule's own configuration did not change, so
			// Terraform never calls ApplyResourceChange on it and never re-reads it.
			// The only refresh in this step ran BEFORE the apply, while the policy was
			// still disabled, so the rule's state correctly still says false. Asserting
			// true here is asserting something no read has happened to observe.
			{
				Config: testAccPolicyRuleDisabledParentConfig(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy.parent", "is_enabled", "true"),
				),
			},
			// Step 3: refresh, then assert the rule followed its parent. This is the
			// first moment a read of the rule happens after the policy was enabled.
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "is_enabled", "true"),
					resource.TestCheckResourceAttr("upwind_threat_policy.parent", "is_enabled", "true"),
				),
			},
			// Step 4: disable the rule explicitly while its policy stays enabled. The
			// rule now OWNS the value rather than inheriting it.
			{
				Config: testAccPolicyRuleDisabledParentConfigWithRule(true, "false"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "is_enabled", "false"),
					func(s *terraform.State) error {
						idBeforeIsEnabledRemoval = s.RootModule().
							Resources["upwind_threat_policy_rule.test"].Primary.ID
						return nil
					},
				),
			},
			// Step 5: remove the line again. The rule must go back to the API default
			// WITHOUT being recreated.
			//
			// Both halves matter. is_enabled reading true proves the reset reached the
			// server: this step's refresh runs before the plan and reads the owned
			// false, so a provider that planned an empty diff would leave false in
			// state. The id proves the reset happened in place - a replacement would
			// also produce true, by destroying the rule and attaching a new one, which
			// takes the detection offline for the duration of the apply.
			{
				Config: testAccPolicyRuleDisabledParentConfig(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "is_enabled", "true"),
					func(s *terraform.State) error {
						got := s.RootModule().Resources["upwind_threat_policy_rule.test"].Primary.ID
						if got != idBeforeIsEnabledRemoval {
							return fmt.Errorf("rule id changed from %s to %s; removing is_enabled "+
								"recreated the rule instead of resetting it in place",
								idBeforeIsEnabledRemoval, got)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestAccPolicyRuleResource_UnrelatedUpdateLeavesAnUnconfiguredIsEnabledAlone guards
// the other side of the reset: a config that never mentioned is_enabled is not a
// removal, and an unrelated edit must not touch the attribute.
//
// A rule can legitimately own false while the config says nothing - every rule written
// by v0.1.1 does, and so does one an operator disabled in the console. Sending the API
// default whenever the config omits the field would turn those back on during an
// unrelated severity edit, with nothing in the plan to say so.
//
// The assertion has to read the SERVER. State is pinned to the planned value here (the
// attribute is Optional+Computed and the config is null, so the plan carries prior
// state), which means a provider that wrongly enabled the rule would still record
// is_enabled = false and pass any state-based check. That is the shape of test that
// cannot fail.
func TestAccPolicyRuleResource_UnrelatedUpdateLeavesAnUnconfiguredIsEnabledAlone(t *testing.T) {
	var policyID, ruleID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_threat_policy_rule",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetPolicyRule(context.Background(), rs.Primary.Attributes["policy_id"], rs.Primary.ID)
				return err
			}),
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyRuleConfig("", ""),
				Check: func(s *terraform.State) error {
					rs := s.RootModule().Resources["upwind_threat_policy_rule.test"]
					policyID, ruleID = rs.Primary.Attributes["policy_id"], rs.Primary.ID
					return nil
				},
			},
			{
				// Out of band, as the console would: disable the rule behind Terraform's
				// back, then make an edit that has nothing to do with is_enabled.
				PreConfig: func() {
					disabled := false
					_, err := testAccClient(t).UpdatePolicyRule(context.Background(), policyID,
						client.UpdatePolicyRuleRequest{ID: ruleID, IsEnabled: &disabled})
					if err != nil {
						t.Fatalf("disabling the rule out of band: %v", err)
					}
				},
				Config: testAccPolicyRuleConfig("high", ""),
				Check: func(s *terraform.State) error {
					pr, err := testAccClient(t).GetPolicyRule(context.Background(), policyID, ruleID)
					if err != nil {
						return err
					}
					if pr.IsEnabled {
						return fmt.Errorf("rule %s is enabled on the server after an unrelated "+
							"severity edit: an omitted is_enabled was sent as a reset, turning a "+
							"disabled detection back on with nothing in the plan to say so", ruleID)
					}
					return nil
				},
			},
		},
	})
}

// TestAccPolicyRuleResource_ExplicitValueMatchingTheEffectiveOneIsStillSent covers a
// value the config states that the API would otherwise never hear.
//
// is_enabled is Optional+Computed and the API reports it as an effective value capped
// by the policy's, so under a DISABLED policy a rule reads false whatever it holds
// server-side. Writing is_enabled = false then matches state exactly: Terraform plans
// nothing, no PATCH is sent, and the rule keeps the API default of true. Enabling the
// policy later turns on a detection the practitioner had declared off.
//
// The fix cannot work through is_enabled itself - Terraform rejects a planned value
// that differs from a known config value - so ModifyPlan marks the write-derived
// attributes unknown instead. Any non-empty plan reaches Update, and Update sends the
// configured value.
func TestAccPolicyRuleResource_ExplicitValueMatchingTheEffectiveOneIsStillSent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_threat_policy_rule",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetPolicyRule(context.Background(), rs.Primary.Attributes["policy_id"], rs.Primary.ID)
				return err
			}),
		Steps: []resource.TestStep{
			// Step 1: disabled policy, rule omits is_enabled. The server stores the API
			// default (true) and the capped read reports false.
			{
				Config: testAccPolicyRuleDisabledParentConfig(false),
				Check: resource.TestCheckResourceAttr(
					"upwind_threat_policy_rule.test", "is_enabled", "false"),
			},
			// Step 2: add is_enabled = false. The attribute itself cannot carry a diff
			// here - config and state both read false - so ExpectNonEmptyPlan is what
			// proves ModifyPlan forced the apply that sends the value.
			{
				Config: testAccPolicyRuleDisabledParentConfigWithRule(false, "false"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectNonEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(
					"upwind_threat_policy_rule.test", "is_enabled", "false"),
			},
			// Step 3: enable the policy. The rule now owns false server-side, so it
			// stays off and nothing drifts. An empty post-apply plan - the harness
			// default - is the assertion; before the fix this step produced
			// "~ is_enabled = true -> false".
			{
				Config: testAccPolicyRuleDisabledParentConfigWithRule(true, "false"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy.parent", "is_enabled", "true"),
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "is_enabled", "false"),
				),
			},
			// Step 4: and it survives a refresh, which is where the old behaviour
			// surfaced the rule as live.
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_threat_policy.parent", "is_enabled", "true"),
					resource.TestCheckResourceAttr("upwind_threat_policy_rule.test", "is_enabled", "false"),
				),
			},
		},
	})
}

// testAccPolicyRuleDisabledParentConfig renders a rule attached to a policy whose
// enabled state is the variable under test. is_enabled is deliberately absent from
// the rule block: the point is what the provider does with a value it must let the
// server decide.
func testAccPolicyRuleDisabledParentConfig(policyEnabled bool) string {
	return testAccPolicyRuleDisabledParentConfigWithRule(policyEnabled, "")
}

// ruleIsEnabled "" omits the attribute, which is what inheritance requires.
func testAccPolicyRuleDisabledParentConfigWithRule(policyEnabled bool, ruleIsEnabled string) string {
	ruleLine := ""
	if ruleIsEnabled != "" {
		ruleLine = "  is_enabled = " + ruleIsEnabled
	}
	return strings.Replace(
		testAccPolicyRuleDisabledParentConfigBase(policyEnabled),
		"resource \"upwind_threat_policy_rule\" \"test\" {",
		"resource \"upwind_threat_policy_rule\" \"test\" {\n"+ruleLine, 1)
}

func testAccPolicyRuleDisabledParentConfigBase(policyEnabled bool) string {
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_threat_policy" "parent" {
  name        = "tf-acc-test-policy-disabled-parent"
  severity    = "low"
  source_type = "cloud_logs"
  is_enabled  = %[1]t

  metadata = {
    detection_title       = "TF Acc Disabled Parent"
    detection_description = "created by acceptance test"
  }
}

resource "upwind_threat_rule_definition" "parent_rd" {
  name            = "tf-acc-test-rd-disabled-parent"
  engine          = "rego"
  threat_category = "cloud_trail_logs"

  rule_expression = <<-REGO
    package policy.custom.cloud_trail_logs

    is_violated(input_item) if {
        input_item.eventName == "TerraformDisabledParentTestEventThatNeverHappens"
    }
  REGO

  metadata = {
    detection_title       = "TF Acc Disabled Parent Rule"
    detection_description = "created by acceptance test"
  }
}

resource "upwind_threat_policy_rule" "test" {
  policy_id          = upwind_threat_policy.parent.id
  rule_definition_id = upwind_threat_rule_definition.parent_rd.id
}
`, policyEnabled)
}

func TestAccMalwareIndicatorResource(t *testing.T) {
	// A syntactically valid sha1 that no real file will match.
	const hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: testAccCheckDestroyed(t, "upwind_malware_indicator",
			func(c *client.Client, rs *terraform.ResourceState) error {
				_, err := c.GetMalwareIndicator(context.Background(), rs.Primary.Attributes["hash"])
				return err
			}),
		Steps: []resource.TestStep{
			{
				Config: testAccMalwareIndicatorConfig(hash, "allow", "created by acceptance test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_malware_indicator.test", "hash", hash),
					resource.TestCheckResourceAttr("upwind_malware_indicator.test", "hash_type", "sha1"),
					resource.TestCheckResourceAttr("upwind_malware_indicator.test", "action", "allow"),
					// id mirrors hash, which is what makes import-by-hash work.
					resource.TestCheckResourceAttr("upwind_malware_indicator.test", "id", hash),
				),
			},
			{
				ResourceName:      "upwind_malware_indicator.test",
				ImportState:       true,
				ImportStateId:     hash,
				ImportStateVerify: true,
				// create_time is not stable between the bulk-create response and a
				// later read: a live run saw 08:15:40 from create and 08:15:41 from
				// import. Server-owned audit data that never affects a plan, so it is
				// excluded from the comparison rather than chased.
				ImportStateVerifyIgnore: []string{"added_by", "create_time"},
			},
			// Changing the verdict must replace rather than update: there is no PATCH.
			{
				Config: testAccMalwareIndicatorConfig(hash, "detect", "created by acceptance test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("upwind_malware_indicator.test", "action", "detect"),
				),
			},
		},
	})
}

// --- configs ---

func testAccRuleDefinitionConfig(name, mitreTactic, threatCategory string) string {
	mitre := ""
	if mitreTactic != "" {
		mitre = fmt.Sprintf("\n    mitre_tactic_code = %q", mitreTactic)
	}
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_threat_rule_definition" "test" {
  name            = %q
  engine          = "rego"
  threat_category = %[3]q

  # Two undocumented API contracts, both enforced with a 422 and neither in the
  # OpenAPI spec:
  #   1. the rule must define is_violated(input_item)
  #   2. the package name must END with the threat_category, so changing the
  #      category means changing the package too
  rule_expression = <<-REGO
    package policy.custom.%[3]s

    is_violated(input_item) if {
        input_item.eventName == "DeleteWebACL"
    }
  REGO

  metadata = {
    detection_title       = "TF Acc Rule Definition"
    detection_description = "created by acceptance test"%[2]s
  }
}
`, name, mitre, threatCategory)
}

// testAccPolicyRuleScopeOverride is a rule-level scope naming a different account
// than the policy's, so a read that returns it proves the rule owns the scope
// rather than inheriting the policy's.
const testAccPolicyRuleScopeOverride = `

  scope = {
    condition = {
      type     = "cloud_account_rule"
      field    = "cloud_account_id"
      operator = "in"
      value    = ["111111111111"]
    }
  }`

// testAccPolicyRuleConfig builds a policy and a rule definition, then attaches
// them. The policy carries a scope so the inherited-scope case is exercised.
func testAccPolicyRuleConfig(severity, scope string) string {
	sev := ""
	if severity != "" {
		sev = fmt.Sprintf("\n  severity = %q", severity)
	}
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_threat_policy" "test" {
  name        = "tf-acc-test-policy-for-rule"
  severity    = "high"
  source_type = "cloud_logs"

  metadata = {
    detection_title       = "TF Acc Detection"
    detection_description = "created by acceptance test"
  }

  resource_scope = {
    condition = {
      type     = "cloud_account_rule"
      field    = "cloud_account_id"
      operator = "in"
      value    = ["%[2]s"]
    }
  }
}

resource "upwind_threat_rule_definition" "test" {
  name            = "tf-acc-test-rd-for-policy"
  engine          = "rego"
  threat_category = "cloud_trail_logs"

  # The API requires an is_violated(input_item) function; a rule without one is
  # rejected with a 422. This contract is documented in the Threats policies
  # user guide, not in the OpenAPI spec.
  rule_expression = <<-REGO
    package policy.custom.cloud_trail_logs

    is_violated(input_item) if {
        input_item.eventName == "DeleteWebACL"
    }
  REGO

  metadata = {
    detection_title       = "TF Acc Rule Definition"
    detection_description = "created by acceptance test"
  }
}

resource "upwind_threat_policy_rule" "test" {
  policy_id          = upwind_threat_policy.test.id
  rule_definition_id = upwind_threat_rule_definition.test.id%[1]s%[3]s
}
`, sev, testAccScopeAccountID(), scope)
}

func testAccMalwareIndicatorConfig(hash, action, reason string) string {
	return fmt.Sprintf(`
provider "upwind" {}

resource "upwind_malware_indicator" "test" {
  hash      = %q
  hash_type = "sha1"
  action    = %q
  reason    = %q
}
`, hash, action, reason)
}

// testAccPolicyRuleImportID builds the composite "<policy-id>/<policy-rule-id>"
// address this resource imports by.
func testAccPolicyRuleImportID(name string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return "", fmt.Errorf("resource %s not found in state", name)
		}
		return rs.Primary.Attributes["policy_id"] + "/" + rs.Primary.ID, nil
	}
}
