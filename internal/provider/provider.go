package provider

import (
	"context"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// Ensure UpwindProvider satisfies the provider.Provider interface at compile time.
var _ provider.Provider = &UpwindProvider{}

// UpwindProvider is the provider implementation.
type UpwindProvider struct {
	// version is set during build and surfaced to the registry / user agent.
	version string
}

// UpwindProviderModel maps the `provider "upwind" {}` block in HCL to Go fields.
// The `tfsdk` tags connect each HCL attribute name to its Go field.
type UpwindProviderModel struct {
	Region       types.String `tfsdk:"region"`
	OrgID        types.String `tfsdk:"org_id"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
}

// New returns a factory that Terraform calls to instantiate the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &UpwindProvider{version: version}
	}
}

// Metadata sets the provider type name ("upwind") used as the prefix for every
// resource and data source, e.g. upwind_access_scope.
func (p *UpwindProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "upwind"
	resp.Version = p.version
}

// Schema declares the configuration accepted inside the `provider "upwind" {}` block.
// Every attribute is Optional so it can also be supplied via environment variable;
// Configure validates that the required values were provided one way or another.
func (p *UpwindProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Upwind provider manages Upwind configuration via the Management REST API v2.",
		Attributes: map[string]schema.Attribute{
			"region": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Upwind region: `" + strings.Join(client.Regions(), "`, `") + "`. " +
					"Selects the API endpoint and OAuth audience. May also be set via the `UPWIND_REGION` environment variable.",
				// Caught during validate/plan, before any client is built. The client
				// still rejects an unknown region (the value may arrive from
				// UPWIND_REGION, which no schema validator can see).
				Validators: []validator.String{
					stringvalidator.OneOf(client.Regions()...),
				},
			},
			"org_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Upwind organization ID (e.g. `org_...`). May also be set via `UPWIND_ORG_ID`.",
			},
			"client_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "OAuth2 client ID for the client-credentials grant. May also be set via `UPWIND_CLIENT_ID`.",
			},
			"client_secret": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "OAuth2 client secret. May also be set via `UPWIND_CLIENT_SECRET`.",
			},
		},
	}
}

// Configure reads provider config, authenticates, and builds the API client.
// Each value may come from HCL or its UPWIND_* environment variable; HCL wins.
// The resulting client is handed to every resource and data source.
func (p *UpwindProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Mask the credential fields before anything else, so that any later log line
	// in this RPC that carries one of these keys prints *** instead of the value.
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "client_secret", "client_id")
	tflog.Debug(ctx, "Configuring the Upwind provider")

	var config UpwindProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Provider config must be known at plan time - reject values that depend on
	// other resources (which are still unknown during planning).
	for name, val := range map[string]types.String{
		"region": config.Region, "org_id": config.OrgID,
		"client_id": config.ClientID, "client_secret": config.ClientSecret,
	} {
		if val.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				path.Root(name),
				"Unknown Upwind provider configuration",
				"The "+name+" value is not known at plan time. Set it to a static value or via the "+
					"UPWIND_"+strings.ToUpper(name)+" environment variable.",
			)
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve each value: environment variable as the default, HCL overrides it.
	region := os.Getenv("UPWIND_REGION")
	orgID := os.Getenv("UPWIND_ORG_ID")
	clientID := os.Getenv("UPWIND_CLIENT_ID")
	clientSecret := os.Getenv("UPWIND_CLIENT_SECRET")

	// Deliberately environment-only, with no provider attribute: region is the
	// supported way to pick an endpoint. This is for Upwind's own testing against
	// staging; client.New rejects a non-http(s) or host-less value.
	endpoint := os.Getenv("UPWIND_ENDPOINT")
	if !config.Region.IsNull() {
		region = config.Region.ValueString()
	}
	if !config.OrgID.IsNull() {
		orgID = config.OrgID.ValueString()
	}
	if !config.ClientID.IsNull() {
		clientID = config.ClientID.ValueString()
	}
	if !config.ClientSecret.IsNull() {
		clientSecret = config.ClientSecret.ValueString()
	}

	// Validate that required values arrived from one source or the other.
	for name, val := range map[string]string{
		"region": region, "org_id": orgID,
		"client_id": clientID, "client_secret": clientSecret,
	} {
		if val == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root(name),
				"Missing Upwind provider configuration",
				"The "+name+" value must be set in the provider block or via the "+
					"UPWIND_"+strings.ToUpper(name)+" environment variable.",
			)
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Region and org id identify the tenant and are safe to log; the credentials
	// are reported only as present/absent, never by value.
	ctx = tflog.SetField(ctx, "upwind_region", region)
	ctx = tflog.SetField(ctx, "upwind_org_id", orgID)
	tflog.Debug(ctx, "Creating the Upwind API client", map[string]any{
		"provider_version":     p.version,
		"user_agent":           client.UserAgent(p.version),
		"endpoint_override":    endpoint != "",
		"region_from_env":      config.Region.IsNull(),
		"org_id_from_env":      config.OrgID.IsNull(),
		"credentials_from_env": config.ClientID.IsNull() && config.ClientSecret.IsNull(),
	})

	// The override redirects every API call, and the bearer token with it, so say
	// so in Terraform's own output rather than only under TF_LOG.
	if endpoint != "" {
		resp.Diagnostics.AddWarning(
			"Upwind API endpoint overridden",
			"UPWIND_ENDPOINT is set, so API calls go to "+endpoint+" instead of the "+region+
				" region, and the OAuth token is minted for it. Unset UPWIND_ENDPOINT to use the region.",
		)
	}

	c, err := client.New(ctx, client.Config{
		Region:          region,
		OrgID:           orgID,
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		Endpoint:        endpoint,
		ProviderVersion: p.version,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Upwind API client", err.Error())
		return
	}
	tflog.Debug(ctx, "Configured the Upwind API client", map[string]any{
		"api_base_url": c.BaseURL(),
	})

	// Hand the client to resources and data sources via their Configure methods.
	resp.ResourceData = c
	resp.DataSourceData = c
}

// Resources lists the managed resources this provider exposes.
func (p *UpwindProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewScopeResource,
		NewThreatPolicyResource,
		NewPolicyRuleResource,
		NewRuleDefinitionResource,
		NewMalwareIndicatorResource,
	}
}

// DataSources lists the read-only data sources.
func (p *UpwindProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewStoryDataSource,
		NewStoriesDataSource,
		NewSkillDataSource,
		NewSkillsDataSource,
		NewConfigurationFindingDataSource,
		NewConfigurationFindingsDataSource,
		NewConfigurationAssetExampleDataSource,
	}
}
