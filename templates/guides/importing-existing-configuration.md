---
page_title: "Adopting existing configuration"
subcategory: ""
description: |-
  Import policies, rules, scopes, and indicators that already exist in Upwind
  instead of recreating them.
---

# Adopting existing configuration

If your policies already exist in Upwind, import them rather than recreating
them. Every resource supports import; the id is the one the API assigns.

```bash
terraform import upwind_access_scope.aws_account uams-xxxxxxxxxxxxxxxx
terraform import upwind_threat_policy.production cp-xxxxxxxxxxxxxxxx

# A policy rule lives under a policy, so its id is composite:
terraform import upwind_threat_policy_rule.production_waf cp-xxxxxxxxxxxxxxxx/cpr-xxxxxxxxxxxxxxxx

# Malware indicators are identified by hash, so no lookup is needed:
terraform import upwind_malware_indicator.installer da39a3ee5e6b4b0d3255bfef95601890afd80709
```

Run `terraform plan` after importing: an empty diff confirms your HCL matches
what the platform already has.

## Letting Terraform write the HCL

If you already have a lot configured, declare what to adopt in `import` blocks
(Terraform 1.5+) instead of transcribing it by hand:

```hcl
# imports.tf
import {
  to = upwind_threat_policy.production
  id = "cp-xxxxxxxxxxxxxxxx"
}

import {
  to = upwind_access_scope.aws_account
  id = "uams-xxxxxxxxxxxxxxxx"
}
```

```bash
terraform plan -generate-config-out=generated.tf
```

Terraform reads each object through the provider and writes matching resource
blocks into `generated.tf`. Review it, keep what you want, then `terraform apply`
to bring it under management.

You still need each object's id - the Upwind console shows them, and malware
indicators need no lookup at all since the hash is the id.
