# A policy applies to the whole organization when resource_scope is omitted.
# This is the usual case: an organization with many cloud accounts does not
# want a policy per account.
resource "upwind_threat_policy" "org_wide" {
  name        = "CloudTrail privilege escalation"
  severity    = "high"
  source_type = "cloud_logs"

  metadata = {
    detection_title       = "Privilege Escalation Attempt"
    detection_description = "IAM changes that grant broad permissions"
  }
}

# Scope it when a policy should only cover part of the estate. Prefer the
# organization or OU condition types over listing individual accounts: they do
# not go stale as accounts are added and removed.
resource "upwind_threat_policy" "production_only" {
  name        = "CloudTrail privilege escalation (production)"
  severity    = "critical"
  source_type = "cloud_logs"
  is_enabled  = true

  metadata = {
    detection_title       = "Privilege Escalation Attempt"
    detection_description = "IAM changes that grant broad permissions in production"
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
