package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

var (
	_ resource.Resource                = &RuleDefinitionResource{}
	_ resource.ResourceWithConfigure   = &RuleDefinitionResource{}
	_ resource.ResourceWithImportState = &RuleDefinitionResource{}
)

// NewRuleDefinitionResource is the factory registered with the provider.
func NewRuleDefinitionResource() resource.Resource {
	return &RuleDefinitionResource{}
}

// RuleDefinitionResource implements upwind_threat_rule_definition.
type RuleDefinitionResource struct {
	client *client.Client
}

type ruleDefinitionResourceModel struct {
	ID             types.String             `tfsdk:"id"`
	Name           types.String             `tfsdk:"name"`
	Engine         types.String             `tfsdk:"engine"`
	ThreatCategory types.String             `tfsdk:"threat_category"`
	RuleExpression types.String             `tfsdk:"rule_expression"`
	Metadata       *ruleDefinitionMetaModel `tfsdk:"metadata"`
	CreateTime     types.String             `tfsdk:"create_time"`
	UpdateTime     types.String             `tfsdk:"update_time"`
	CreatorID      types.String             `tfsdk:"creator_id"`
	LastModifierID types.String             `tfsdk:"last_modifier_id"`
}

type ruleDefinitionMetaModel struct {
	DetectionTitle       types.String `tfsdk:"detection_title"`
	DetectionDescription types.String `tfsdk:"detection_description"`
	MitreTacticCode      types.String `tfsdk:"mitre_tactic_code"`
	MitreTacticName      types.String `tfsdk:"mitre_tactic_name"`
	MitreTechniqueCode   types.String `tfsdk:"mitre_technique_code"`
	MitreTechniqueName   types.String `tfsdk:"mitre_technique_name"`
}

func (r *RuleDefinitionResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_rule_definition"
}

func (r *RuleDefinitionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Upwind threat rule definition: a Rego expression that detects a threat, attachable to one or more threat policies.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this rule definition (server-generated). Maps to the API's `rule_definition_id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Rule definition name.",
			},
			// The bulk edit endpoint accepts neither engine nor threat_category, so
			// changing either cannot be expressed as an update.
			"engine": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Detection engine. Only `rego` is supported. Immutable: changing it forces replacement.",
				Validators: []validator.String{
					stringvalidator.OneOf("rego"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"threat_category": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Threat category this rule detects. One of `k8s_audit_logs`, `network_traffic`, `process_execution`, `file_events`, `cloud_trail_logs`, `syscall_event`, `azure_activity_logs`, `azure_entra_id_logs`, `gcp_audit_logs`, `api_events`. Immutable: changing it forces replacement.",
				Validators: []validator.String{
					stringvalidator.OneOf("k8s_audit_logs", "network_traffic", "process_execution", "file_events", "cloud_trail_logs", "syscall_event", "azure_activity_logs", "azure_entra_id_logs", "gcp_audit_logs", "api_events"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"rule_expression": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Rego expression body. Must begin with a package declaration matching `package policy.custom.<threat_category>`. Re-validated upstream on every change.",
			},
			"metadata": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: "Display and MITRE ATT&CK metadata for detections raised by this rule.",
				Attributes: map[string]schema.Attribute{
					"detection_title": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Title shown on a detection, e.g. `Unauthorized API Call Detection`.",
					},
					"detection_description": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Description shown on a detection.",
					},
					"mitre_tactic_code": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "MITRE ATT&CK tactic code, e.g. `TA0001`.",
					},
					"mitre_tactic_name": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "MITRE ATT&CK tactic name, e.g. `Initial Access`.",
					},
					"mitre_technique_code": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "MITRE ATT&CK technique code, e.g. `T1078`.",
					},
					"mitre_technique_name": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "MITRE ATT&CK technique name, e.g. `Valid Accounts`.",
					},
				},
			},
			// DRIFT DEFENSE: server-owned audit fields, only known after apply.
			//
			// None of them carries UseStateForUnknown. The bulk write endpoints return a
			// PARTIAL rule definition: creator_id and last_modifier_id are omitted
			// entirely, and the timestamps are re-stamped. Promising the stored value
			// during planning would make apply contradict its own plan ("Provider
			// produced inconsistent result after apply"). Left unknown during a write,
			// which is what they actually are.
			"create_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the rule definition was created.",
			},
			"update_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the rule definition was last updated.",
			},
			"creator_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the user or client that created this rule definition.",
			},
			"last_modifier_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the user or client that last modified this rule definition.",
			},
		},
	}
}

func (r *RuleDefinitionResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = c
}

func (r *RuleDefinitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ruleDefinitionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rd, err := r.client.CreateRuleDefinition(ctx, client.CreateRuleDefinitionRequest{
		Name:           plan.Name.ValueString(),
		Engine:         plan.Engine.ValueString(),
		ThreatCategory: plan.ThreatCategory.ValueString(),
		RuleExpression: plan.RuleExpression.ValueString(),
		Metadata:       ruleDefinitionMetaToAPI(plan.Metadata),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error creating rule definition", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, ruleDefinitionToModel(rd, plan.Metadata))...)
}

func (r *RuleDefinitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ruleDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rd, err := r.client.GetRuleDefinition(ctx, state.ID.ValueString())
	if err != nil {
		// DRIFT DEFENSE: deleted out-of-band -> remove from state for clean recreation.
		if client.IsNotFound(err) {
			logGoneFromState(ctx, state.ID.ValueString())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading rule definition", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, ruleDefinitionToModel(rd, state.Metadata))...)
}

func (r *RuleDefinitionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ruleDefinitionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	expr := plan.RuleExpression.ValueString()
	meta := ruleDefinitionMetaToAPI(plan.Metadata)

	rd, err := r.client.UpdateRuleDefinition(ctx, client.UpdateRuleDefinitionRequest{
		ID:             plan.ID.ValueString(),
		Name:           &name,
		RuleExpression: &expr,
		Metadata:       &meta,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error updating rule definition", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, ruleDefinitionToModel(rd, plan.Metadata))...)
}

func (r *RuleDefinitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ruleDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Treat an already-gone rule definition as success (idempotent delete).
	if err := r.client.DeleteRuleDefinition(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error deleting rule definition", err.Error())
	}
}

// ImportState adopts an existing rule definition by id.
func (r *RuleDefinitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// --- mapping helpers ---

func ruleDefinitionMetaToAPI(m *ruleDefinitionMetaModel) client.RuleDefinitionMeta {
	if m == nil {
		return client.RuleDefinitionMeta{}
	}
	return client.RuleDefinitionMeta{
		DetectionTitle:       m.DetectionTitle.ValueString(),
		DetectionDescription: m.DetectionDescription.ValueString(),
		MitreTacticCode:      m.MitreTacticCode.ValueString(),
		MitreTacticName:      m.MitreTacticName.ValueString(),
		MitreTechniqueCode:   m.MitreTechniqueCode.ValueString(),
		MitreTechniqueName:   m.MitreTechniqueName.ValueString(),
	}
}

// ruleDefinitionToModel converts an API rule definition into Terraform state.
// prior carries the configured metadata so unset optional MITRE fields stay null
// instead of flipping to "" (see preserveNull).
func ruleDefinitionToModel(rd *client.RuleDefinition, prior *ruleDefinitionMetaModel) ruleDefinitionResourceModel {
	if prior == nil {
		prior = &ruleDefinitionMetaModel{}
	}
	return ruleDefinitionResourceModel{
		ID:             types.StringValue(rd.RuleDefinitionID),
		Name:           types.StringValue(rd.Name),
		Engine:         types.StringValue(rd.Engine),
		ThreatCategory: types.StringValue(rd.ThreatCategory),
		RuleExpression: types.StringValue(rd.RuleExpression),
		Metadata: &ruleDefinitionMetaModel{
			DetectionTitle:       types.StringValue(rd.Metadata.DetectionTitle),
			DetectionDescription: types.StringValue(rd.Metadata.DetectionDescription),
			// DRIFT DEFENSE: null/empty equivalence for the optional MITRE fields.
			MitreTacticCode:    preserveNull(rd.Metadata.MitreTacticCode, prior.MitreTacticCode),
			MitreTacticName:    preserveNull(rd.Metadata.MitreTacticName, prior.MitreTacticName),
			MitreTechniqueCode: preserveNull(rd.Metadata.MitreTechniqueCode, prior.MitreTechniqueCode),
			MitreTechniqueName: preserveNull(rd.Metadata.MitreTechniqueName, prior.MitreTechniqueName),
		},
		CreateTime:     types.StringValue(rd.CreateTime),
		UpdateTime:     types.StringValue(rd.UpdateTime),
		CreatorID:      types.StringValue(rd.CreatorID),
		LastModifierID: types.StringValue(rd.LastModifierID),
	}
}

// preserveNull keeps an optional string null when the API returns it empty and
// the practitioner never set it. Without this, an unset optional attribute reads
// back as "" and every plan shows drift. Mirrors the description handling in
// scopeToModel.
func preserveNull(apiValue string, prior types.String) types.String {
	if apiValue == "" && prior.IsNull() {
		return types.StringNull()
	}
	return types.StringValue(apiValue)
}
