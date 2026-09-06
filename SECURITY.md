# Security Policy

## Reporting a vulnerability in this provider

Report security issues in `terraform-provider-upwind` through GitHub's private
vulnerability reporting: open the
[Security tab](https://github.com/upwindsecurity/terraform-provider-upwind/security)
and choose **Report a vulnerability**. The report stays private to the
maintainers until a fix is published.

Please do not open a public issue for a security report.

Useful things to include: the provider version, the Terraform version, the
resource or data source involved, and what an attacker gains. A `TF_LOG=DEBUG`
excerpt helps - **redact your credentials and organization id first**; see the
troubleshooting notes in the [README](README.md#troubleshooting) for what the
provider does and does not log.

## Vulnerabilities in the Upwind platform

This policy covers the provider only. For the Upwind platform or its APIs, use
Upwind's own disclosure process rather than this repository.

## Supported versions

The most recent minor release receives security fixes. Older releases are not
patched - the provider is distributed through the Terraform Registry, so
upgrading is a version-constraint change.

## Credentials, and what this provider does with them

The provider reads an OAuth2 client id and secret and exchanges them for a
short-lived bearer token. Notes for operators:

- Prefer the `UPWIND_CLIENT_ID` / `UPWIND_CLIENT_SECRET` environment variables
  over literals in `.tf` files, which end up in version control.
- `client_secret` is marked sensitive in the schema, so Terraform redacts it in
  plan and apply output. Both credential fields are masked in provider logs.
- **Terraform state is not encrypted at rest by Terraform itself.** Provider
  credentials are not written to state, but resource attributes are - use a
  backend with encryption and access control.
- The provider sends requests only to `api.upwind.io`, its regional
  equivalents (`api.eu.upwind.io`, `api.me.upwind.io`), and
  `auth.upwind.io` for the token exchange. There is no telemetry.
