# An access-management scope is a named filter selecting a slice of resources.
#
# The values must name cloud accounts your organization has onboarded.
resource "upwind_access_scope" "production_aws" {
  name        = "Production AWS"
  description = "Resources in the production AWS accounts"

  resource_filters = [
    {
      attribute = "cloud_account_id"
      operator  = "in"
      values    = ["123456789012", "210987654321"]
    }
  ]
}
