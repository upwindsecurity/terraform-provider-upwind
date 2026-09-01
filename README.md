# terraform-provider-upwind

A [Terraform](https://www.terraform.io) provider for managing [Upwind](https://www.upwind.io)
configuration through the Upwind Management REST API v2.

Define your detection policies, custom rules, access scopes, and malware
indicators as code. A policy change becomes a reviewable diff with history and a
rollback, and the same configuration can be applied across every organization
you operate instead of being recreated by hand in each one.

Useful links:

- [Provider documentation](https://registry.terraform.io/providers/upwindsecurity/upwind/latest/docs) -
  every resource, data source, and guide, on the Terraform Registry
- [Upwind documentation](https://docs.upwind.io)
- [Terraform documentation](https://developer.hashicorp.com/terraform/docs)
- [Developing the provider](#developing-the-provider) - below

> **Status: not yet published.** Until the first release is tagged, the registry
> links above do not resolve and the provider has to be built from this
> repository - see [Developing the provider](#developing-the-provider).

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
  (>= 1.5 for `import` blocks)
- An Upwind organization and an OAuth2 client (client ID + secret) with access to
  the Management API
- [Go](https://go.dev/dl/) >= 1.25 - only to build the provider from source

## Using the provider

```hcl
terraform {
  required_providers {
    upwind = {
      source  = "upwindsecurity/upwind"
      version = "~> 0.1"
    }
  }
}

# Credentials are read from the environment, which is the recommended setup.
provider "upwind" {}
```

```bash
export UPWIND_REGION=us              # us | eu | me | ap
export UPWIND_ORG_ID=org_xxxxxxxxxxxx
 export UPWIND_CLIENT_ID=xxxxxxxx
 export UPWIND_CLIENT_SECRET=xxxxxxxx

terraform init
terraform plan
```

Every setting can also be given in the `provider` block, where it takes
precedence over the environment variable. The leading space on the credential
lines keeps them out of shell history in most shells.

The [provider documentation](https://registry.terraform.io/providers/upwindsecurity/upwind/latest/docs)
covers the full configuration reference, all five resources, all seven data
sources, and guides for custom detections, adopting existing configuration,
gating a deploy on findings, and multi-organization setups.

> These resources are security controls. A `terraform destroy` disables
> detections. Review the plan.

## Developing the provider

**Every `make` target runs from the root of this repository** - the directory
holding the `Makefile`. None of them run from your Terraform project.

```bash
make build      # binary in the repo root - NOT the one dev_overrides uses
make install    # $GOBIN - this is the one Terraform picks up
make fmt        # gofmt -s
make vet        # go vet
make lint       # golangci-lint
make docs       # regenerate docs/ from the schemas, examples/, and templates/
make test       # fast unit tests - no tenant required
make testacc    # acceptance tests - real Terraform lifecycle against a live tenant
```

To run Terraform against your local build instead of the registry, add a
`dev_overrides` block to `~/.terraformrc` pointing at your `$GOBIN` (find it with
`go env GOBIN`, which falls back to `$(go env GOPATH)/bin`):

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/upwindsecurity/upwind" = "/Users/you/go/bin"
  }
  # For all other providers, install from the registry as normal.
  direct {}
}
```

With overrides active, **skip `terraform init`** - Terraform uses the local
binary directly, and `init` would fail trying to fetch a provider it does not
need. A warning on every command reminds you overrides are on; that is expected.

Use `make install`, not `make build`: `build` leaves the binary in the repo root,
which `dev_overrides` does not look at, so you would silently keep testing an
older version. Re-run `make install` after every code change, then re-run
`terraform plan` in your Terraform project directory.

### Docs

`docs/` is generated but **committed**: the Terraform Registry renders the
markdown in this repository and never runs the generator itself, so a schema
change that skips `make docs` ships stale documentation. Regenerate it in the
same commit as any schema, `examples/`, or `templates/` change.

`make docs` needs [tfplugindocs](https://github.com/hashicorp/terraform-plugin-docs):

```bash
go install github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@latest
```

It reads `examples/` by strict path convention -
`examples/resources/<type_name>/resource.tf` and `import.sh`,
`examples/data-sources/<type_name>/data-source.tf` - and embeds each file into
that type's generated page. A new resource without a matching directory still
generates, silently, with an empty usage section.

Hand-written pages live in `templates/`: `index.md.tmpl` is the provider landing
page, and `templates/guides/*.md` are copied to `docs/guides/`. Editing `docs/`
directly is pointless - the next `make docs` overwrites it. Verify with
`tfplugindocs validate`.

### Testing

Acceptance tests require the four `UPWIND_*` credentials above plus
`UPWIND_TEST_ACCOUNT_ID`, the cloud account the scope-bearing tests target. There
is no default - it must be a real onboarded account in the tenant you are running
against, because access scopes validate `cloud_account_id` referentially and
reject anything the tenant does not own.

```bash
export UPWIND_TEST_ACCOUNT_ID=123456789012
```

### Troubleshooting

Every API call the provider makes is logged. Set `TF_LOG=DEBUG` (or
`TF_LOG_PROVIDER=DEBUG` for provider lines only) and re-run the failing command:

```bash
TF_LOG=DEBUG terraform apply 2>&1 | tee tf.log
grep "Upwind API" tf.log
```

Each request logs the HTTP method and URL, the response status, its size, and how
long it took, alongside the Terraform operation it belongs to (`tf_rpc`) and the
resource or data source that triggered it (`tf_resource_type` /
`tf_data_source_type`). A read that finds its object gone upstream logs that too,
which is what explains an unexpected recreate in the next plan.

Credentials are never logged, and neither are request or response bodies. The
response body of a *failed* call is not in the log but is in the error Terraform
prints, so include both when opening a support ticket - with the
`upwind_request_id` from the log line if one is present.

## Project layout

```
main.go                       Entry point - serves the provider.
internal/provider/            Provider definition, resources, data sources, tests.
internal/client/              Upwind Management API client.
examples/                     Usage examples, embedded into the generated docs.
templates/                    Hand-written docs: index page and guides.
docs/                         Generated registry docs. Committed - see above.
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the codebase is organized.

## License

[Mozilla Public License 2.0](LICENSE).
