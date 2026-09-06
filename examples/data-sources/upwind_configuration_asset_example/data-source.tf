# An example asset of a given kind. Its purpose is authoring the Rego for a
# configuration custom rule: what you need is the SHAPE of the document your
# policy will be evaluated against, not any particular field.
#
# The payload is a JSON string, not a typed object. An aws_s3_bucket and a
# kubernetes_pod share almost no fields, so there is no schema to declare -
# decode what you need with jsondecode().
data "upwind_configuration_asset_example" "bucket" {
  asset_kind = "aws_s3_bucket"
}

# Optionally draw the example from one specific cloud account.
data "upwind_configuration_asset_example" "bucket_in_prod" {
  asset_kind       = "aws_s3_bucket"
  cloud_account_id = "123456789012"
}

locals {
  example_bucket = jsondecode(data.upwind_configuration_asset_example.bucket.assets_json)[0]
}

# Inspect the field names your Rego will reference. Note the payload uses the
# cloud provider's own camelCase keys, not Upwind's snake_case API convention.
output "bucket_field_names" {
  value = keys(local.example_bucket)
}
