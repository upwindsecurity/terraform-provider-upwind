# Configuration findings are read-only: the platform produces one each time a
# compliance rule is evaluated against a resource, so Terraform cannot own them.
#
# At least one filter is REQUIRED. There is no unfiltered list endpoint for
# findings, and the search endpoint rejects an empty condition set, so "give me
# everything" cannot be expressed.
#
# Note a finding exists for a PASSING check too - filter on status unless you
# actually want both.
#
# Every finding returned is written to state and printed in the plan, and a
# finding is a large object. Filter narrowly and cap the read.
data "upwind_configuration_findings" "failing_criticals" {
  # Paging stops here, so this bounds the API calls and the state file both.
  max_results = 100

  filters = [
    {
      field    = "status"
      operator = "eq"
      value    = ["fail"]
    },
    {
      field    = "severity"
      operator = "in"
      value    = ["high", "critical"]
    }
  ]
}

# The durable use is as a gate - surface a count your pipeline can act on.
output "failing_critical_count" {
  value = length(data.upwind_configuration_findings.failing_criticals.findings)
}

# A capped read makes that count a floor, not a total - wrong in the reassuring
# direction, so fail on it rather than gate on it.
check "finding_count_is_complete" {
  assert {
    condition     = !data.upwind_configuration_findings.failing_criticals.truncated
    error_message = "More findings matched than max_results returned - the count above is a floor, not a total. Narrow the filters or raise max_results."
  }
}

# This data source omits rule.description, rule.remediation and
# framework.description - long text that would be persisted for every finding.
# Read one finding by id when you need the fix instructions.
data "upwind_configuration_finding" "worst" {
  id = data.upwind_configuration_findings.failing_criticals.findings[0].id
}

output "how_to_fix_the_first_one" {
  value = data.upwind_configuration_finding.worst.rule.remediation
}

# Filtering by cloud account tags: values must be in "key=value" form. A bare key
# matches no findings.
data "upwind_configuration_findings" "production" {
  max_results = 100

  filters = [
    {
      field    = "cloud_account_tags"
      operator = "in"
      value    = ["environment=production"]
    }
  ]
}
