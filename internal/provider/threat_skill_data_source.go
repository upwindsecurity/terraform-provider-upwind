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
	_ datasource.DataSource              = &SkillDataSource{}
	_ datasource.DataSourceWithConfigure = &SkillDataSource{}
	_ datasource.DataSource              = &SkillsDataSource{}
	_ datasource.DataSourceWithConfigure = &SkillsDataSource{}
)

// NewSkillDataSource and NewSkillsDataSource are the factories registered with
// the provider.
func NewSkillDataSource() datasource.DataSource  { return &SkillDataSource{} }
func NewSkillsDataSource() datasource.DataSource { return &SkillsDataSource{} }

// SkillDataSource implements upwind_threat_skill: one Agent Skill's metadata by
// name. SkillsDataSource implements upwind_threat_skills: all of them.
//
// Only metadata is exposed. The skill body is served by
// GET /threats/skills/{skill-name} as an application/zip binary, which has no
// useful representation in Terraform state.
type SkillDataSource struct {
	client *client.Client
}

type SkillsDataSource struct {
	client *client.Client
}

type skillModel struct {
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Version     types.String `tfsdk:"version"`
}

type skillsDataSourceModel struct {
	Skills []skillModel `tfsdk:"skills"`
}

func (d *SkillDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_skill"
}

func (d *SkillsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_skills"
}

// skillAttributes is the shared attribute set for one skill, used both as the
// top level of upwind_threat_skill and as the element of upwind_threat_skills.
func skillAttributes(nameRequired bool) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Required:            nameRequired,
			Computed:            !nameRequired,
			MarkdownDescription: "Unique identifier for this skill, e.g. `threat-policy-manager`. Also the path segment used to download it.",
		},
		"description": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "What this skill does and when an agent should use it. Agents match against this text when deciding whether the skill is relevant.",
		},
		"version": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "The skill's published version.",
		},
	}
}

func (d *SkillDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the metadata of a single Upwind threat Agent Skill by name. The skill body itself is a zip download and is not exposed.",
		Attributes:          skillAttributes(true),
	}
}

func (d *SkillsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the metadata of every published Upwind threat Agent Skill.",
		Attributes: map[string]schema.Attribute{
			"skills": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "All published threat Agent Skills.",
				NestedObject:        schema.NestedAttributeObject{Attributes: skillAttributes(false)},
			},
		},
	}
}

func (d *SkillDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *SkillsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

// configureDataSourceClient unwraps the provider's client, reporting a provider
// bug if the type is wrong. Returns nil before the provider is configured, which
// is normal during early plan phases.
func configureDataSourceClient(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) *client.Client {
	if req.ProviderData == nil {
		return nil
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("expected *client.Client, got %T. This is a provider bug.", req.ProviderData),
		)
		return nil
	}
	return c
}

func (d *SkillDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config skillModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	skill, err := d.client.GetSkill(ctx, config.Name.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError(
				"Threat Agent Skill not found",
				fmt.Sprintf("no skill named %q is published for this organization. "+
					"Use the upwind_threat_skills data source to list available skills.", config.Name.ValueString()),
			)
			return
		}
		resp.Diagnostics.AddError("Error reading threat Agent Skill", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, skillModel{
		Name:        types.StringValue(skill.Name),
		Description: types.StringValue(skill.Description),
		Version:     types.StringValue(skill.Version),
	})...)
}

func (d *SkillsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	skills, err := d.client.ListSkills(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading threat Agent Skills", err.Error())
		return
	}

	state := skillsDataSourceModel{Skills: make([]skillModel, 0, len(skills))}
	for _, s := range skills {
		state.Skills = append(state.Skills, skillModel{
			Name:        types.StringValue(s.Name),
			Description: types.StringValue(s.Description),
			Version:     types.StringValue(s.Version),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}
