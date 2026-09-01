---
page_title: "Custom detections, end to end"
subcategory: ""
description: |-
  Build a custom threat detection from its Rego logic, the policy carrying its
  severity and scope, and the attachment joining them.
---

# Custom detections, end to end

A custom threat detection is three resources: the Rego logic, the policy that
carries severity and scope, and the attachment joining them. Terraform derives
the ordering from the references, so this applies in one pass.

```hcl
# 1. The detection logic. Stands alone, and can be attached to many policies.
resource "upwind_threat_rule_definition" "waf_deletion" {
  name            = "detect-waf-deletion"
  engine          = "rego"
  threat_category = "cloud_trail_logs"

  # The expression must define is_violated(input_item), and its package name
  # must end with the threat_category above.
  rule_expression = <<-REGO
    package policy.custom.cloud_trail_logs

    is_violated(input_item) if {
        input_item.eventName == "DeleteWebACL"
    }
  REGO

  metadata = {
    detection_title       = "WAF Web ACL Deleted"
    detection_description = "A WAF Web ACL was deleted, removing request filtering"
  }
}

# 2. The policy: severity, telemetry source, and which resources it covers.
#    Omit resource_scope to cover the whole organization.
resource "upwind_threat_policy" "production" {
  name        = "CloudTrail privilege escalation (production)"
  severity    = "critical"
  source_type = "cloud_logs"
  is_enabled  = true

  metadata = {
    detection_title       = "Privilege Escalation Attempt"
    detection_description = "IAM changes granting broad permissions in production"
  }

  resource_scope = {
    condition = {
      type     = "cloud_account_ou_rule"
      field    = "cloud_account_ou_id"
      operator = "in"
      value    = ["ou-1234-abcdefgh"]
    }
  }
}

# 3. The attachment. Destroying this detaches the rule; the definition survives.
resource "upwind_threat_policy_rule" "production_waf" {
  policy_id          = upwind_threat_policy.production.id
  rule_definition_id = upwind_threat_rule_definition.waf_deletion.id
}
```

Destroying the attachment detaches the rule and leaves the definition in place,
so the same definition can be attached to another policy without rebuilding it.

These resources are security controls: a `terraform destroy` disables
detections. Review the plan.
