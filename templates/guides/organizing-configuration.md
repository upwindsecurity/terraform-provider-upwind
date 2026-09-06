---
page_title: "Organizing your configuration"
subcategory: ""
description: |-
  How Terraform reads a configuration directory, and how to serve more than one
  Upwind organization or region.
---

# Organizing your configuration

`main.tf` is only a convention. Terraform reads **every `*.tf` file in the
directory you run it from** and merges them into one configuration, so split
them however you like - resources can reference each other across files, and the
order does not matter:

```
upwind-config/
├── providers.tf     # terraform{} and provider{} blocks
├── policies.tf      # upwind_threat_policy
├── rules.tf         # upwind_threat_rule_definition + upwind_threat_policy_rule
├── scopes.tf        # upwind_access_scope
└── gates.tf         # data sources and check blocks
```

Terraform does **not** read subdirectories. A nested directory is only included
if you reference it as a module:

```hcl
module "detections" {
  source = "./modules/detections"
}
```

A directory is also the unit of state: two sibling directories are two
independent configurations with two state files.

## Multiple organizations or regions

The `region` setting pins the API host and the OAuth audience together, so one
provider instance serves one region and one organization. Use aliases for more,
and a module to avoid duplicating the resources:

```hcl
provider "upwind" {
  alias  = "eu"
  region = "eu"
  org_id = var.eu_org_id
}

module "detections_eu" {
  source    = "./modules/detections"
  providers = { upwind = upwind.eu }
}
```
