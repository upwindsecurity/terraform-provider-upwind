# Changelog

Notable changes to this provider, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. The provider follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, a minor version may carry a breaking change; breaking changes always
appear under their own **Breaking** heading.

## [0.1.2] - 2026-11-05

### Fixed

- `upwind_threat_policy_rule.is_enabled` now behaves as documented in every
  direction. Omitting it follows the policy. Setting it always reaches the API,
  including when the platform already reports the same value. Removing it restores
  the API default in place, so the rule keeps its id and stays attached. An omitted
  value is left alone by edits to other attributes.

- `upwind_threat_policy` no longer risks failing an apply with "inconsistent result
  after apply" on update. Only the server-populated audit fields are taken from the
  post-write read.

## [0.1.1] - 2026-09-08

### Fixed

- `upwind_threat_policy_rule` could not be attached to a policy with
  `is_enabled = false`. The platform reports a rule's enabled state as an
  effective value capped by its policy's, so the rule read back as disabled
  while the schema's static default had promised `true`, and every apply failed
  with "Provider produced inconsistent result after apply". The attribute is now
  computed when omitted, so it takes whatever the platform reports. Staging a
  policy disabled and attaching rules before enabling it works as expected.

  Setting `is_enabled = true` explicitly on a rule whose policy is disabled
  still fails the apply, which is correct - that state cannot exist. (The API
  accepts the write; it is the capped read disagreeing with the plan that fails.)

### Changed

- `is_enabled` on `upwind_threat_policy_rule` no longer documents a default of
  `true`. An omitted value is inherited, not defaulted. Configurations that set
  the attribute explicitly are unaffected, and an omitted one keeps its value in
  state, so no plan changes for existing users.

## [0.1.0] - 2026-09-06

First release.

### Resources

- `upwind_access_scope` - access-management scopes
- `upwind_threat_policy` - threat detection policies
- `upwind_threat_rule_definition` - custom detection rule definitions
- `upwind_threat_policy_rule` - rule definitions attached to a policy
- `upwind_malware_indicator` - file hash verdict overrides

### Data sources

- `upwind_threat_story` / `upwind_threat_stories` - threat stories, individually
  or as a filtered collection
- `upwind_threat_skill` / `upwind_threat_skills` - published agent skills
- `upwind_configuration_finding` / `upwind_configuration_findings` - compliance
  findings, individually or as a filtered collection
- `upwind_configuration_asset_example` - an example asset document of a given
  kind, for authoring custom configuration rules

### Provider

- OAuth2 client-credentials authentication against the Upwind Management API
- Support for the `us`, `eu`, `me`, and `ap` regions
- Every setting configurable in HCL or through its `UPWIND_*` environment
  variable, with HCL taking precedence
- Import support on all five resources, for adopting configuration that already
  exists in your organization
- Credentials and request bodies are never written to logs
