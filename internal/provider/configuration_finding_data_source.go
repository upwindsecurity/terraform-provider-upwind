package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

var (
	_ datasource.DataSource              = &ConfigurationFindingDataSource{}
	_ datasource.DataSourceWithConfigure = &ConfigurationFindingDataSource{}
	_ datasource.DataSource              = &ConfigurationFindingsDataSource{}
	_ datasource.DataSourceWithConfigure = &ConfigurationFindingsDataSource{}
)

// NewConfigurationFindingDataSource is the factory registered with the provider.
func NewConfigurationFindingDataSource() datasource.DataSource {
	return &ConfigurationFindingDataSource{}
}

// NewConfigurationFindingsDataSource is the factory registered with the provider.
func NewConfigurationFindingsDataSource() datasource.DataSource {
	return &ConfigurationFindingsDataSource{}
}

// ConfigurationFindingDataSource implements upwind_configuration_finding: one
// compliance finding by id.
//
// Findings are produced by the platform when a rule is evaluated against a
// resource, so they can only ever be read, never managed as a resource.
type ConfigurationFindingDataSource struct {
	client *client.Client
}

// ConfigurationFindingsDataSource implements upwind_configuration_findings: every
// finding matching a required set of filters, with cursor pagination followed to
// exhaustion.
// configurationFindingToListItemModel projects the full model rather than
// converting again, so the collection cannot drift from the singular data source
// on a shared field - the resource block's null handling in particular.
func configurationFindingToListItemModel(ctx context.Context, f client.ConfigurationFinding) (configurationFindingListItemModel, diag.Diagnostics) {
	full, diags := configurationFindingToModel(ctx, f)
	return configurationFindingListItemModel{
		ID:             full.ID,
		Title:          full.Title,
		Severity:       full.Severity,
		Status:         full.Status,
		EvaluationTime: full.EvaluationTime,
		FirstSeenTime:  full.FirstSeenTime,
		RiskCategories: full.RiskCategories,
		Framework: &configurationFindingFrameworkListItemModel{
			ID:                full.Framework.ID,
			Title:             full.Framework.Title,
			CloudProviderName: full.Framework.CloudProviderName,
			Status:            full.Framework.Status,
			Revision:          full.Framework.Revision,
			Version:           full.Framework.Version,
		},
		Rule: &configurationFindingRuleListItemModel{
			ID:    full.Rule.ID,
			Title: full.Rule.Title,
		},
		Resource: full.Resource,
	}, diags
}

type ConfigurationFindingsDataSource struct {
	client *client.Client
}

// configurationFindingModel serves both data sources: as the whole state of the
// singular one, and as an element of the plural one's list. The two differ only
// in whether `id` is supplied or computed.
type configurationFindingModel struct {
	ID             types.String `tfsdk:"id"`
	Title          types.String `tfsdk:"title"`
	Severity       types.String `tfsdk:"severity"`
	Status         types.String `tfsdk:"status"`
	EvaluationTime types.String `tfsdk:"evaluation_time"`
	FirstSeenTime  types.String `tfsdk:"first_seen_time"`
	RiskCategories types.List   `tfsdk:"risk_categories"`

	Framework *configurationFindingFrameworkModel `tfsdk:"framework"`
	Resource  *configurationFindingResourceModel  `tfsdk:"resource"`
	Rule      *configurationFindingRuleModel      `tfsdk:"rule"`
}

type configurationFindingFrameworkModel struct {
	ID                types.String `tfsdk:"id"`
	Title             types.String `tfsdk:"title"`
	Description       types.String `tfsdk:"description"`
	CloudProviderName types.String `tfsdk:"cloud_provider_name"`
	Status            types.String `tfsdk:"status"`
	Revision          types.String `tfsdk:"revision"`
	Version           types.String `tfsdk:"version"`
}

type configurationFindingRuleModel struct {
	ID          types.String `tfsdk:"id"`
	Title       types.String `tfsdk:"title"`
	Description types.String `tfsdk:"description"`
	Remediation types.String `tfsdk:"remediation"`
}

type configurationFindingResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	ARN               types.String `tfsdk:"arn"`
	CloudAccountID    types.String `tfsdk:"cloud_account_id"`
	CloudAccountName  types.String `tfsdk:"cloud_account_name"`
	CloudProviderName types.String `tfsdk:"cloud_provider_name"`
	ClusterID         types.String `tfsdk:"cluster_id"`
	Namespace         types.String `tfsdk:"namespace"`
	Region            types.String `tfsdk:"region"`
	SyncTime          types.String `tfsdk:"sync_time"`
	UpwindAssetID     types.String `tfsdk:"upwind_asset_id"`
}

// The *ListItemModel types are the collection's projection of a finding. They
// drop the three unbounded prose fields - rule.description, rule.remediation and
// framework.description - which together are about half the bytes of a finding
// and are only readable one at a time anyway. Every result a data source returns
// is written to the Terraform state file and printed in the plan, so a
// collection pays that cost per finding, on every operation, forever.
//
// upwind_configuration_finding returns the full record, so nothing is
// unreachable - see configurationFindingModel.
type configurationFindingListItemModel struct {
	ID             types.String `tfsdk:"id"`
	Title          types.String `tfsdk:"title"`
	Severity       types.String `tfsdk:"severity"`
	Status         types.String `tfsdk:"status"`
	EvaluationTime types.String `tfsdk:"evaluation_time"`
	FirstSeenTime  types.String `tfsdk:"first_seen_time"`
	RiskCategories types.List   `tfsdk:"risk_categories"`

	Framework *configurationFindingFrameworkListItemModel `tfsdk:"framework"`
	Resource  *configurationFindingResourceModel          `tfsdk:"resource"`
	Rule      *configurationFindingRuleListItemModel      `tfsdk:"rule"`
}

type configurationFindingFrameworkListItemModel struct {
	ID                types.String `tfsdk:"id"`
	Title             types.String `tfsdk:"title"`
	CloudProviderName types.String `tfsdk:"cloud_provider_name"`
	Status            types.String `tfsdk:"status"`
	Revision          types.String `tfsdk:"revision"`
	Version           types.String `tfsdk:"version"`
}

type configurationFindingRuleListItemModel struct {
	ID    types.String `tfsdk:"id"`
	Title types.String `tfsdk:"title"`
}

type configurationFindingFilterModel struct {
	Field    types.String `tfsdk:"field"`
	Operator types.String `tfsdk:"operator"`
	Value    types.List   `tfsdk:"value"`
}

type configurationFindingsDataSourceModel struct {
	Filters    []configurationFindingFilterModel   `tfsdk:"filters"`
	PageSize   types.Int64                         `tfsdk:"page_size"`
	MaxResults types.Int64                         `tfsdk:"max_results"`
	Truncated  types.Bool                          `tfsdk:"truncated"`
	Findings   []configurationFindingListItemModel `tfsdk:"findings"`
}

// findingBodyAttributes is the finding's own fields. idAttribute differs: the
// singular data source takes the id as input, the plural computes it.
//
// detail adds the three prose fields, and is set only by the singular data
// source - see configurationFindingListItemModel for why the collection omits
// them. Gated here rather than by a second attribute map so the two data sources
// cannot drift in the fields they do share.
func findingBodyAttributes(idAttribute schema.Attribute, detail bool) map[string]schema.Attribute {
	frameworkAttributes := map[string]schema.Attribute{
		"id":                  schema.StringAttribute{Computed: true, MarkdownDescription: "Framework identifier."},
		"title":               schema.StringAttribute{Computed: true, MarkdownDescription: "Framework title."},
		"cloud_provider_name": schema.StringAttribute{Computed: true, MarkdownDescription: "Cloud provider the framework applies to."},
		"status": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the framework is `enabled` or `disabled`. A string here, though the frameworks write endpoints model the same concept as an `is_enabled` boolean.",
		},
		"revision": schema.StringAttribute{Computed: true, MarkdownDescription: "Framework revision."},
		"version":  schema.StringAttribute{Computed: true, MarkdownDescription: "Framework version."},
	}
	ruleAttributes := map[string]schema.Attribute{
		"id":    schema.StringAttribute{Computed: true, MarkdownDescription: "Rule identifier."},
		"title": schema.StringAttribute{Computed: true, MarkdownDescription: "Rule title."},
	}
	if detail {
		frameworkAttributes["description"] = schema.StringAttribute{Computed: true, MarkdownDescription: "Framework description."}
		ruleAttributes["description"] = schema.StringAttribute{Computed: true, MarkdownDescription: "What the rule checks."}
		ruleAttributes["remediation"] = schema.StringAttribute{Computed: true, MarkdownDescription: "How to remediate a failing resource."}
	}

	return map[string]schema.Attribute{
		"id": idAttribute,
		"title": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Human-readable title of the finding.",
		},
		"severity": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Severity: `low`, `medium`, `high`, or `critical`. Lowercase, matching configuration rules and unlike the uppercase severities on threat stories.",
		},
		"status": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Evaluation outcome: `pass` or `fail`. Note a finding exists for a passing check too, so filter on this rather than assuming every finding is a violation.",
		},
		"evaluation_time": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "ISO8601 timestamp of the most recent evaluation.",
		},
		"first_seen_time": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "ISO8601 timestamp when this finding was first observed.",
		},
		"risk_categories": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Risk categories this finding falls under.",
		},
		"framework": schema.SingleNestedAttribute{
			Computed:            true,
			MarkdownDescription: "The compliance framework the finding's rule belongs to.",
			Attributes:          frameworkAttributes,
		},
		"rule": schema.SingleNestedAttribute{
			Computed:            true,
			MarkdownDescription: "The rule that produced this finding.",
			Attributes:          ruleAttributes,
		},
		"resource": schema.SingleNestedAttribute{
			Computed:            true,
			MarkdownDescription: "The cloud resource the rule was evaluated against.",
			Attributes: map[string]schema.Attribute{
				"id":                  schema.StringAttribute{Computed: true, MarkdownDescription: "Resource identifier."},
				"name":                schema.StringAttribute{Computed: true, MarkdownDescription: "Resource name."},
				"type":                schema.StringAttribute{Computed: true, MarkdownDescription: "Resource type, e.g. `aws_s3_bucket`."},
				"arn":                 schema.StringAttribute{Computed: true, MarkdownDescription: "Cloud provider ARN, where the provider has one."},
				"cloud_account_id":    schema.StringAttribute{Computed: true, MarkdownDescription: "Cloud account containing the resource."},
				"cloud_account_name":  schema.StringAttribute{Computed: true, MarkdownDescription: "Cloud account display name."},
				"cloud_provider_name": schema.StringAttribute{Computed: true, MarkdownDescription: "One of `aws`, `gcp`, `azure`, `oracle`, or `byoc`."},
				"cluster_id":          schema.StringAttribute{Computed: true, MarkdownDescription: "Cluster identifier, for Kubernetes resources."},
				"namespace":           schema.StringAttribute{Computed: true, MarkdownDescription: "Namespace, for Kubernetes resources."},
				"region":              schema.StringAttribute{Computed: true, MarkdownDescription: "Cloud region."},
				"sync_time":           schema.StringAttribute{Computed: true, MarkdownDescription: "ISO8601 timestamp when Upwind last synced the resource."},
				"upwind_asset_id":     schema.StringAttribute{Computed: true, MarkdownDescription: "Upwind's own asset identifier."},
			},
		},
	}
}

// configurationFindingToModel converts one API finding into the shared model.
func configurationFindingToModel(ctx context.Context, f client.ConfigurationFinding) (configurationFindingModel, diag.Diagnostics) {
	riskCategories, diags := types.ListValueFrom(ctx, types.StringType, f.RiskCategories)

	return configurationFindingModel{
		ID:             types.StringValue(f.ID),
		Title:          types.StringValue(f.Title),
		Severity:       types.StringValue(f.Severity),
		Status:         types.StringValue(f.Status),
		EvaluationTime: types.StringValue(f.EvaluationTime),
		FirstSeenTime:  types.StringValue(f.FirstSeenTime),
		RiskCategories: riskCategories,
		Framework: &configurationFindingFrameworkModel{
			ID:                types.StringValue(f.Framework.ID),
			Title:             types.StringValue(f.Framework.Title),
			Description:       types.StringValue(f.Framework.Description),
			CloudProviderName: types.StringValue(f.Framework.CloudProviderName),
			Status:            types.StringValue(f.Framework.Status),
			Revision:          types.StringValue(f.Framework.Revision),
			Version:           types.StringValue(f.Framework.Version),
		},
		Rule: &configurationFindingRuleModel{
			ID:          types.StringValue(f.Rule.ID),
			Title:       types.StringValue(f.Rule.Title),
			Description: types.StringValue(f.Rule.Description),
			Remediation: types.StringValue(f.Rule.Remediation),
		},
		Resource: &configurationFindingResourceModel{
			ID:   types.StringValue(f.Resource.ID),
			Name: types.StringValue(f.Resource.Name),
			Type: types.StringValue(f.Resource.Type),
			// These three are conditional on the resource's kind, and their schema
			// descriptions say so. They must stay null when absent: a practitioner
			// branching on `cluster_id == null` to mean "not a Kubernetes resource"
			// gets the wrong branch if the field reads back as "".
			ARN:               preserveNull(f.Resource.ARN, types.StringNull()),
			ClusterID:         preserveNull(f.Resource.ClusterID, types.StringNull()),
			Namespace:         preserveNull(f.Resource.Namespace, types.StringNull()),
			CloudAccountID:    types.StringValue(f.Resource.CloudAccountID),
			CloudAccountName:  types.StringValue(f.Resource.CloudAccountName),
			CloudProviderName: types.StringValue(f.Resource.CloudProviderName),
			Region:            types.StringValue(f.Resource.Region),
			SyncTime:          types.StringValue(f.Resource.SyncTime),
			UpwindAssetID:     types.StringValue(f.Resource.UpwindAssetID),
		},
	}, diags
}

// --- upwind_configuration_finding (singular) ---

func (d *ConfigurationFindingDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_configuration_finding"
}

func (d *ConfigurationFindingDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a single Upwind configuration (compliance) finding by ID. Findings are produced by the platform when a rule is evaluated against a resource, so they cannot be managed as a resource. " +
			"This is the full record: unlike `upwind_configuration_findings`, it includes `rule.description`, `rule.remediation` and `framework.description`.",
		Attributes: findingBodyAttributes(schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Unique identifier of the finding to read.",
		}, true),
	}
}

func (d *ConfigurationFindingDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *ConfigurationFindingDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config configurationFindingModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	finding, err := d.client.GetConfigurationFinding(ctx, config.ID.ValueString())
	if err != nil {
		// A data source pointing at a missing object is a config error, not silent
		// drift: unlike a resource there is no state to remove, so fail loudly.
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError(
				"Configuration finding not found",
				fmt.Sprintf("no configuration finding with ID %q exists in this organization.", config.ID.ValueString()),
			)
			return
		}
		resp.Diagnostics.AddError("Error reading configuration finding", err.Error())
		return
	}

	model, diags := configurationFindingToModel(ctx, *finding)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// --- upwind_configuration_findings (plural) ---

func (d *ConfigurationFindingsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_configuration_findings"
}

func (d *ConfigurationFindingsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads Upwind configuration (compliance) findings matching a set of filters. " +
			"At least one filter is required: the API has no unfiltered list endpoint for findings and rejects an empty condition set. " +
			"Pages are followed until `max_results` is reached, or to exhaustion when it is unset." + collectionStateWarning,
		Attributes: mergeAttributes(paginationAttributes("findings"), map[string]schema.Attribute{
			"filters": schema.ListNestedAttribute{
				Required: true,
				MarkdownDescription: "Conditions to filter by. At least one is required. Multiple filters are combined by the API. " +
					"A condition on a field the data does not populate matches nothing and raises no error, so an empty result is worth double-checking against the filter itself.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"field": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Field to filter on. One of `status`, `severity`, `evaluation_time`, `first_seen_time`, `upwind_asset_id`, `resource_name`, `rule_title`, `rule_id`, `framework_id`, `framework_title`, `cloud_account_tags`.",
						},
						"operator": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Comparison operator. `eq` or `in` for exact matches; `gt`, `gte`, `lt`, `lte` for range comparisons on the time fields.",
							// Both collections' filters serialize through the same
							// searchCondition body (internal/client/malware_indicators.go)
							// to the same v2 /search endpoints, yet the two spec-derived
							// comments disagree on range operators: findings document
							// gt/lt (client/configurations.go), stories gte/lte
							// (client/stories.go). No acceptance test covers either - only
							// eq and in. Until a live call settles it, accept the union.
							// A validator that rejects an operator the API does take would
							// make time-range filtering unexpressible with no workaround;
							// the API still rejects whatever it does not support.
							Validators: []validator.String{
								stringvalidator.OneOf("eq", "in", "gt", "gte", "lt", "lte"),
							},
						},
						"value": schema.ListAttribute{
							Required:            true,
							ElementType:         types.StringType,
							MarkdownDescription: "Values to compare against. For `cloud_account_tags` each value must be in `key=value` form (e.g. `environment=production`); a bare key silently matches nothing.",
						},
					},
				},
			},
			"findings": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "Matching findings, in the order the API returned them. " +
					"`rule.description`, `rule.remediation` and `framework.description` are deliberately omitted here: " +
					"they are long text, about half the size of a finding, and every result is persisted to state. " +
					"Read `upwind_configuration_finding` with an id from this list for the full record.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: findingBodyAttributes(schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Unique identifier for this finding.",
					}, false),
				},
			},
		}),
	}
}

func (d *ConfigurationFindingsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *ConfigurationFindingsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config configurationFindingsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := make([]client.ConfigurationFindingFilter, 0, len(config.Filters))
	for _, f := range config.Filters {
		var values []string
		resp.Diagnostics.Append(f.Value.ElementsAs(ctx, &values, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		filters = append(filters, client.ConfigurationFindingFilter{
			Field:    f.Field.ValueString(),
			Operator: f.Operator.ValueString(),
			Value:    values,
		})
	}

	findings, truncated, err := d.client.SearchConfigurationFindings(ctx, filters,
		int(config.PageSize.ValueInt64()), int(config.MaxResults.ValueInt64()))
	if err != nil {
		// `filters = []` satisfies Required, so the empty case still reaches the
		// client. Translate it into an actionable message rather than surfacing a
		// bare error, since the fix is a config change.
		if errors.Is(err, client.ErrFiltersRequired) {
			resp.Diagnostics.AddAttributeError(
				path.Root("filters"),
				"At least one filter is required",
				"upwind_configuration_findings cannot list every finding: the API has no unfiltered list endpoint for findings and rejects an empty condition set. "+
					"Add a filter, for example status = fail or severity in [high, critical].",
			)
			return
		}
		resp.Diagnostics.AddError("Error reading configuration findings", err.Error())
		return
	}
	config.Truncated = types.BoolValue(truncated)

	config.Findings = make([]configurationFindingListItemModel, 0, len(findings))
	for _, f := range findings {
		model, diags := configurationFindingToListItemModel(ctx, f)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		config.Findings = append(config.Findings, model)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
