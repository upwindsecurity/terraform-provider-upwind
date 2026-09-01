terraform {
  required_providers {
    upwind = {
      source  = "upwindsecurity/upwind"
      version = "~> 0.1"
    }
  }
}

# Credentials are read from the environment, which is the recommended setup:
#   UPWIND_REGION         us | eu | me
#   UPWIND_ORG_ID         org_...
#   UPWIND_CLIENT_ID
#   UPWIND_CLIENT_SECRET
provider "upwind" {}

# Or set them explicitly. Keep the secret in a variable, never a literal.
provider "upwind" {
  alias         = "explicit"
  region        = "us"
  org_id        = var.upwind_org_id
  client_id     = var.upwind_client_id
  client_secret = var.upwind_client_secret
}
