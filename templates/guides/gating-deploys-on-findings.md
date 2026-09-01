---
page_title: "Gating a deploy on live findings"
subcategory: ""
description: |-
  Use a data source and a check block to stop a deploy while critical
  configuration findings are open.
---

# Gating a deploy on live findings

Data sources read the platform at plan time, so a deploy can refuse to proceed
while findings are open.

```hcl
data "upwind_configuration_findings" "criticals" {
  # A gate only needs to know whether ANY exist, so cap the read at one. The
  # whole result is written to state and printed in the plan; there is no reason
  # to persist thousands of findings to answer a yes/no question.
  max_results = 1

  filters = [
    { field = "status", operator = "eq", value = ["fail"] },
    { field = "severity", operator = "in", value = ["critical"] },
  ]
}

check "no_critical_misconfigurations" {
  assert {
    condition     = length(data.upwind_configuration_findings.criticals.findings) == 0
    error_message = "Critical configuration findings are open - resolve before deploying."
  }
}
```

Three things to know before relying on this:

- **Filter on `status`.** A finding exists for a passing check too, so an
  unfiltered count is not a count of problems.
- **Every result is written to the Terraform state file and printed in the plan.**
  State is read and rewritten on every operation, so a large result set is a tax
  on every later plan, not just this one. Keep the filters narrow and set
  `max_results`.
- **The list omits the long text.** `rule.description`, `rule.remediation` and
  `framework.description` are about half the size of a finding and are only
  readable one at a time, so they are not in `upwind_configuration_findings`.
  Read `upwind_configuration_finding` with an id from the list when you need them.
- **`page_size` is not a cap.** It only chooses how the fetch is chunked; paging
  continues past it. `max_results` is the attribute that bounds what comes back.

## When the count itself is the answer

The gate above is safe at `max_results = 1` because it asks a yes/no question.
A gate that reports a number is different - a capped read makes that number a
floor, not a total, and it is wrong in the reassuring direction. Read
`truncated` and fail on it:

```hcl
data "upwind_configuration_findings" "criticals" {
  max_results = 500

  filters = [
    { field = "status", operator = "eq", value = ["fail"] },
    { field = "severity", operator = "in", value = ["critical"] },
  ]
}

output "critical_finding_count" {
  value = length(data.upwind_configuration_findings.criticals.findings)
}

check "count_is_complete" {
  assert {
    condition     = !data.upwind_configuration_findings.criticals.truncated
    error_message = "More findings matched than max_results returned - the count is a floor, not a total."
  }
}
```
