# Changelog

Notable changes to this provider, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. The provider follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html);
below 1.0 a minor version may carry a breaking change, so breaking changes always
get their own **Breaking** heading.

## Cutting a release

Rename `## [Unreleased]` to `## [x.y.z] - YYYY-MM-DD` and add a fresh empty
`## [Unreleased]` above it before the tag is cut. The release workflow reads the
section matching the tag and fails if there is none, so this file is the source
of the published release notes.

## [Unreleased]

First release. Everything is new, so it is listed by surface rather than repeated
under Added.

### Resources

- `upwind_access_scope` - access-management scopes
- `upwind_threat_policy` - threat detection policies
- `upwind_threat_policy_rule` - rules attached to a threat policy
- `upwind_threat_rule_definition` - custom detection rule definitions
- `upwind_malware_indicator` - malware indicators

### Data sources

- `upwind_threat_story` / `upwind_threat_stories` - platform-generated threat
  stories, singular and filtered collection
- `upwind_threat_skill` / `upwind_threat_skills` - detection skills
- `upwind_configuration_finding` / `upwind_configuration_findings` - compliance
  findings, singular and filtered collection
- `upwind_configuration_asset_example` - an example asset document of a given
  kind, for authoring Rego in a custom configuration rule

### Provider

- OAuth2 client-credentials authentication against the Upwind Management REST
  API v2, with the token pinned to a region through the `audience` parameter
- `us`, `eu`, and `me` regions
- Every attribute settable in HCL or through its `UPWIND_*` environment
  variable; HCL wins
- Token-endpoint failures reported without echoing the upstream response body
- `tflog` request logging at the client's single choke point, with credentials
  masked and request/response bodies never logged
