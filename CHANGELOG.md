# Changelog

Notable changes to this provider, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. The provider follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, a minor version may carry a breaking change; breaking changes always
appear under their own **Breaking** heading.

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
