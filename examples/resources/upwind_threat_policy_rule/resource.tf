# A policy rule ATTACHES a rule definition to a policy. It is the join between
# the two, not a copy of the logic: destroying it detaches the rule and leaves
# the definition intact.
resource "upwind_threat_policy_rule" "prod_waf" {
  policy_id          = upwind_threat_policy.production_only.id
  rule_definition_id = upwind_threat_rule_definition.waf_deletion.id
}

# The same definition attached to a second policy, with overrides. Omit
# severity or scope to inherit the policy's; set them to override.
resource "upwind_threat_policy_rule" "sandbox_waf" {
  policy_id          = upwind_threat_policy.org_wide.id
  rule_definition_id = upwind_threat_rule_definition.waf_deletion.id

  severity = "low"

  scope = {
    condition = {
      type     = "cloud_account_rule"
      field    = "cloud_account_id"
      operator = "in"
      value    = ["123456789012"]
    }
  }
}
