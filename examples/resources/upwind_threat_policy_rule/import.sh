# A policy rule lives under a policy, so it imports by a composite address:
#   <policy-id>/<policy-rule-id>
terraform import upwind_threat_policy_rule.prod_waf cp-xxxxxxxxxxxxxxxx/cpr-xxxxxxxxxxxxxxxx
