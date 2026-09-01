# A single story by id. This is the only endpoint that returns `description`
# and `status_reason`; the collection endpoints omit them.
#
# A story id that does not exist is an error, not an empty result: a data
# source has no state to drop, so a missing object fails the plan.
data "upwind_threat_story" "incident" {
  id = "sty-1a2b3c4d5e6f7890"
}

output "incident_summary" {
  value = {
    title    = data.upwind_threat_story.incident.title
    severity = data.upwind_threat_story.incident.severity
    status   = data.upwind_threat_story.incident.status
  }
}
