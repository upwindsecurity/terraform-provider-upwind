# A rule definition holds the detection logic. It exists on its own and can be
# attached to any number of policies, so write it once and reuse it.
resource "upwind_threat_rule_definition" "waf_deletion" {
  name            = "detect-waf-deletion"
  engine          = "rego"
  threat_category = "cloud_trail_logs"

  # The rule expression must satisfy two requirements:
  #   1. it defines is_violated(input_item)
  #   2. its package name ends with the threat_category set above
  rule_expression = <<-REGO
    package policy.custom.cloud_trail_logs

    is_violated(input_item) if {
        input_item.eventName == "DeleteWebACL"
    }
  REGO

  metadata = {
    detection_title       = "WAF Web ACL Deleted"
    detection_description = "A WAF Web ACL was deleted, removing request filtering"

    # Optional MITRE ATT&CK mapping.
    mitre_tactic_code    = "TA0005"
    mitre_technique_code = "T1562"
  }
}
