package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

var (
	_ datasource.DataSource              = &StoriesDataSource{}
	_ datasource.DataSourceWithConfigure = &StoriesDataSource{}
)

// NewStoriesDataSource is the factory registered with the provider.
func NewStoriesDataSource() datasource.DataSource {
	return &StoriesDataSource{}
}

// StoriesDataSource implements upwind_threat_stories: every story matching an
// optional set of filters, with cursor pagination followed to exhaustion.
type StoriesDataSource struct {
	client *client.Client
}

type storiesDataSourceModel struct {
	Filters    []storyFilterModel   `tfsdk:"filters"`
	PageSize   types.Int64          `tfsdk:"page_size"`
	MaxResults types.Int64          `tfsdk:"max_results"`
	Truncated  types.Bool           `tfsdk:"truncated"`
	Stories    []storyListItemModel `tfsdk:"stories"`
}

type storyFilterModel struct {
	Field    types.String `tfsdk:"field"`
	Operator types.String `tfsdk:"operator"`
	Value    types.List   `tfsdk:"value"`
}

// storyListItemModel deliberately omits description and status_reason: the
// collection endpoints do not return them, and exposing always-null attributes
// would imply the data is available here when it is not. Use
// upwind_threat_story for a full record.
type storyListItemModel struct {
	ID           types.String `tfsdk:"id"`
	Title        types.String `tfsdk:"title"`
	Severity     types.String `tfsdk:"severity"`
	Status       types.String `tfsdk:"status"`
	DetectionIDs types.List   `tfsdk:"detection_ids"`
	CreateTime   types.String `tfsdk:"create_time"`
	UpdateTime   types.String `tfsdk:"update_time"`
}

func (d *StoriesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_stories"
}

func (d *StoriesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads Upwind threat stories, optionally filtered. Pages are followed until `max_results` " +
			"is reached, or to exhaustion when it is unset." + collectionStateWarning,
		Attributes: mergeAttributes(paginationAttributes("stories"), map[string]schema.Attribute{
			"filters": schema.ListNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Conditions to filter by. Omit to return every story. Multiple filters are combined by the API.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"field": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Field to filter on. One of `severity`, `status`, `create_time`, `update_time`.",
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
							MarkdownDescription: "Values to compare against.",
						},
					},
				},
			},
			"stories": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Matching stories, in the order the API returned them.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Unique identifier for this story.",
						},
						"title": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Story title.",
						},
						"severity": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`.",
						},
						"status": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Status: `OPEN` or `ARCHIVED`.",
						},
						"detection_ids": schema.ListAttribute{
							Computed:            true,
							ElementType:         types.StringType,
							MarkdownDescription: "IDs of the detections that make up this story.",
						},
						"create_time": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "ISO8601 timestamp when the story was created.",
						},
						"update_time": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "ISO8601 timestamp when the story was last updated.",
						},
					},
				},
			},
		}),
	}
}

func (d *StoriesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("expected *client.Client, got %T. This is a provider bug.", req.ProviderData),
		)
		return
	}
	d.client = c
}

func (d *StoriesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config storiesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := make([]client.StoryFilter, 0, len(config.Filters))
	for _, f := range config.Filters {
		var values []string
		resp.Diagnostics.Append(f.Value.ElementsAs(ctx, &values, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		filters = append(filters, client.StoryFilter{
			Field:    f.Field.ValueString(),
			Operator: f.Operator.ValueString(),
			Value:    values,
		})
	}

	stories, truncated, err := d.client.ListStories(ctx, filters,
		int(config.PageSize.ValueInt64()), int(config.MaxResults.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Error reading threat stories", err.Error())
		return
	}
	config.Truncated = types.BoolValue(truncated)

	config.Stories = make([]storyListItemModel, 0, len(stories))
	for _, s := range stories {
		detectionIDs, diags := types.ListValueFrom(ctx, types.StringType, s.DetectionIDs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		config.Stories = append(config.Stories, storyListItemModel{
			ID:           types.StringValue(s.ID),
			Title:        types.StringValue(s.Title),
			Severity:     types.StringValue(s.Severity),
			Status:       types.StringValue(s.Status),
			DetectionIDs: detectionIDs,
			CreateTime:   types.StringValue(s.CreateTime),
			UpdateTime:   types.StringValue(s.UpdateTime),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
