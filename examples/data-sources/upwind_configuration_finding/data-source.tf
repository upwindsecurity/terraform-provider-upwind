# A single finding by id. This is the endpoint to use when you need the rule's
# remediation text or the full resource identity, and it returns a richer
# framework object than the collection endpoint does.
#
# A finding id that does not exist is an error, not an empty result: a data source
# has no state to drop, so a missing object fails the plan.
data "upwind_configuration_finding" "public_bucket" {
  id = "cf-1a2b3c4d5e6f7890"
}

output "remediation" {
  value = {
    title       = data.upwind_configuration_finding.public_bucket.title
    severity    = data.upwind_configuration_finding.public_bucket.severity
    status      = data.upwind_configuration_finding.public_bucket.status
    resource    = data.upwind_configuration_finding.public_bucket.resource.name
    region      = data.upwind_configuration_finding.public_bucket.resource.region
    remediation = data.upwind_configuration_finding.public_bucket.rule.remediation
  }
}
