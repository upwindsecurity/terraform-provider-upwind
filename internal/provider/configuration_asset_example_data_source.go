package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

var (
	_ datasource.DataSource              = &ConfigurationAssetExampleDataSource{}
	_ datasource.DataSourceWithConfigure = &ConfigurationAssetExampleDataSource{}
)

// NewConfigurationAssetExampleDataSource is the factory registered with the provider.
func NewConfigurationAssetExampleDataSource() datasource.DataSource {
	return &ConfigurationAssetExampleDataSource{}
}

// ConfigurationAssetExampleDataSource implements
// upwind_configuration_asset_example: a sample asset of a given kind, as raw JSON.
//
// This exists to support authoring Rego for a configuration custom rule, where
// what you need is the shape of the input document your policy will be evaluated
// against.
type ConfigurationAssetExampleDataSource struct {
	client *client.Client
}

type configurationAssetExampleModel struct {
	AssetKind      types.String `tfsdk:"asset_kind"`
	CloudAccountID types.String `tfsdk:"cloud_account_id"`
	AssetsJSON     types.String `tfsdk:"assets_json"`
}

func (d *ConfigurationAssetExampleDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_configuration_asset_example"
}

func (d *ConfigurationAssetExampleDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads an example asset of a given kind, as raw JSON. " +
			"Useful when authoring the Rego for a configuration custom rule, which is evaluated against a document of this shape.",
		Attributes: map[string]schema.Attribute{
			"asset_kind": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Kind of asset to fetch an example of, e.g. `aws_s3_bucket` or `kubernetes_pod`.",
			},
			"cloud_account_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Draw the example from this cloud account. Omit to let Upwind pick any account in the organization.",
			},
			"assets_json": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "A JSON array of example assets. " +
					"Returned as a string rather than a typed object because the shape differs per asset kind - an `aws_s3_bucket` and a `kubernetes_pod` share almost no fields, so there is no schema to declare. " +
					"Decode it in HCL with `jsondecode()`.",
			},
		},
	}
}

func (d *ConfigurationAssetExampleDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *ConfigurationAssetExampleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config configurationAssetExampleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	raw, err := d.client.GetAssetExample(ctx, config.AssetKind.ValueString(), config.CloudAccountID.ValueString())
	if err != nil {
		// An unknown kind, or a kind with nothing onboarded, comes back empty. Both
		// are config errors from a practitioner's point of view: there is no state
		// to drop, so say so rather than returning silently empty.
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError(
				"No asset example available",
				fmt.Sprintf(
					"the API returned no example for asset kind %q. Either the kind does not exist, or this organization has no asset of that kind onboarded%s.",
					config.AssetKind.ValueString(),
					accountSuffix(config.CloudAccountID),
				),
			)
			return
		}
		resp.Diagnostics.AddError("Error reading asset example", err.Error())
		return
	}

	config.AssetsJSON = types.StringValue(string(raw))
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// accountSuffix names the account in an error message when one was requested, so
// a practitioner can tell "nothing of this kind anywhere" from "nothing of this
// kind in the account I asked about".
func accountSuffix(cloudAccountID types.String) string {
	if cloudAccountID.IsNull() || cloudAccountID.ValueString() == "" {
		return ""
	}
	return fmt.Sprintf(" in cloud account %q", cloudAccountID.ValueString())
}
