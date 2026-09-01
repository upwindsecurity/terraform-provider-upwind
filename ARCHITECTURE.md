# Architecture

How the Upwind Terraform provider is structured, and how a request flows from a
customer's `.tf` file all the way to the Upwind API.

---

## 1. The big picture

A Terraform provider is a standalone binary. Terraform launches it as a
subprocess and talks to it over gRPC, so the provider never runs inside
Terraform and Terraform never links this code.

```
   ┌──────────────────────────────┐        ┌──────────────────────────────┐
   │  Go source + tests           │        │  main.tf  (HCL)              │
   │            │                 │        │     │                        │
   │   make build / release       │        │  terraform init / apply      │
   │            │                 │        │     │                        │
   │            ▼                 │        │     ▼                        │
   │   signed provider binary ───────────► │  downloaded from the Registry │
   └──────────────────────────────┘ publish└──────────────────────────────┘
```

A release is published to the Terraform Registry as signed, per-platform
archives; `terraform init` fetches the one matching the caller's OS and
architecture and verifies the signature before running it.

---

## 2. Layered architecture (the request path)

Each layer depends only on the one below it. Built and tested bottom-up.

```
┌─────────────────────────────────────────────────────────────┐
│  Terraform CLI                                                │  ← customer runs this
└─────────────────────────────────────────────────────────────┘
                         │ gRPC (plugin protocol v6)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Provider          internal/provider/provider.go             │
│   • declares the `provider "upwind" {}` config block          │
│   • Configure(): resolve config (HCL/env) → validate → build  │
│     the client → inject it into every resource & data source  │
└─────────────────────────────────────────────────────────────┘
                         │ passes *client.Client
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Resources / Data sources   internal/provider/*_resource.go   │
│   • upwind_access_scope, upwind_threat_policy,                │
│     upwind_threat_policy_rule, upwind_threat_rule_definition,  │
│     upwind_malware_indicator                                   │
│   • data sources: upwind_threat_story/stories/skill/skills,    │
│     upwind_configuration_finding/findings/asset_example         │
│   • schema + Create/Read/Update/Delete/ImportState            │
│   • translate Terraform state <-> client types                │
└─────────────────────────────────────────────────────────────┘
                         │ calls GetScope / CreateScope / ...
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  API client         internal/client/                          │
│   client.go    region → audience, OAuth2 token (auto-refresh) │
│   request.go   doRequest(): URL build, JSON, status → APIError │
│   scopes.go / threat_policies.go / policy_rules.go /          │
│   rule_definitions.go / malware_indicators.go / stories.go /  │
│   skills.go / configurations.go - one file per API surface,    │
│   each with its types and Get/Search/Create/Update/Delete      │
└─────────────────────────────────────────────────────────────┘
                         │ HTTPS + Bearer token
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Upwind Management REST API v2                                │
│   https://api{.eu|.me}.upwind.io/v2/organizations/{org}/...   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Components and responsibilities

| Component | File(s) | Responsibility |
|-----------|---------|----------------|
| **Entry point** | `main.go` | Serves the provider over the plugin protocol. |
| **Provider** | `internal/provider/provider.go` | Config block schema; `Configure()` does resolve → validate → build client → inject. |
| **Auth** | `internal/client/client.go` | Maps region to API host + OAuth `audience`; builds an auto-caching/refreshing token source. No network until first call. |
| **Request layer** | `internal/client/request.go` | One `doRequest` helper: builds org-scoped URLs, encodes/decodes JSON, maps non-2xx → `APIError`; `IsNotFound` for 404 handling. |
| **Scope API** | `internal/client/scopes.go` | `Scope` type + `Get/Create/Update/DeleteScope`; unwraps the `{items:[...]}` envelope. |
| **Threats API** | `internal/client/threat_policies.go`, `policy_rules.go`, `rule_definitions.go`, `malware_indicators.go` | Policies, rule attachments, Rego rule definitions, and hash overrides. Writes go through bulk endpoints. |
| **Read-only APIs** | `internal/client/stories.go`, `skills.go`, `configurations.go` | Threat stories, Agent Skills, and configuration findings; the search-backed ones follow cursor pagination to exhaustion. |
| **Resources** | `internal/provider/*_resource.go` | Terraform resources; thin glue between state and the client. |
| **Data sources** | `internal/provider/*_data_source.go` | Read-only lookups; the stories list follows cursor pagination. |
| **Tests** | `*_test.go` | Unit tests (regions, request path via httptest) + acceptance harness (`testAccProtoV6ProviderFactories`). |

---

## 4. Request flow example - `terraform apply` creating a scope

```
1. terraform apply
2. Terraform starts the provider, calls Configure() once
       → region "us" → audience https://api.upwind.io
       → OAuth2 token source ready (token fetched lazily)
       → client injected into the scope resource
3. Scope resource Create():
       → builds CreateScopeRequest{name, description, resource_filters}
       → client.CreateScope(ctx, req)
4. client.doRequest("POST", "/access-management/scopes", body):
       → URL: https://api.upwind.io/v2/organizations/org_.../access-management/scopes
       → first call triggers token fetch; Bearer token attached automatically
       → POST, read response, unwrap items[0]
5. Create() writes the returned id + timestamps into Terraform state
```

---

## 5. Design principles

- **One direction of dependency.** Each layer above depends only on the one
  below it: resources know the client, the client knows nothing about Terraform.
- **Auth solved once.** Resources never touch tokens or regions - the client,
  injected via `Configure`, hides all of it.
- **Shared work lives in one place.** URL building, JSON and errors live in the
  request layer, so resources stay tiny. Pagination is the outstanding exception:
  the cursor loop is duplicated in `internal/client/stories.go` and
  `internal/client/configurations.go`. It was left in place while stories was the
  only consumer; the second one has landed, so it is due to move into
  `request.go`.
- **Set semantics for unordered data.** API arrays returned in arbitrary order
  (`resource_filters`, `values`, permissions) are modeled as sets to prevent false drift.
- **Config from HCL or env.** Provider config is `Optional` in schema but required
  at runtime; secrets can come from `UPWIND_*` env vars instead of `.tf` files.
- **Region pinning.** The OAuth `audience` must match the regional host; the client
  derives both from the configured region.

---
