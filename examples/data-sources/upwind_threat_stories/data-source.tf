# Threat stories are read-only: they are produced by detections, so Terraform
# cannot create or own one. Story ids are per-incident and go stale when the
# incident closes, so do not reference them from resource configuration.
#
# The durable use is as a gate - surface a count your pipeline can act on.
#
# Every story returned is written to state and printed in the plan, so filter
# narrowly and cap the read.
data "upwind_threat_stories" "open_criticals" {
  # Paging stops here, so this bounds the API calls and the state file both.
  max_results = 100

  filters = [
    {
      field    = "status"
      operator = "eq"
      value    = ["OPEN"]
    },
    {
      field    = "severity"
      operator = "eq"
      # Uppercase: story severities are CRITICAL/HIGH/MEDIUM/LOW/INFO, unlike the
      # lowercase severities on threat policies and configuration findings.
      value = ["CRITICAL"]
    }
  ]
}

output "open_critical_story_count" {
  value = length(data.upwind_threat_stories.open_criticals.stories)
}

# The count above is a floor, not a total, whenever this is true.
output "open_critical_story_count_is_capped" {
  value = data.upwind_threat_stories.open_criticals.truncated
}
