package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// Interface checks: full resource, receives the client, supports `terraform import`.
var (
	_ resource.Resource                = &ThreatPolicyResource{}
	_ resource.ResourceWithConfigure   = &ThreatPolicyResource{}
	_ resource.ResourceWithImportState = &ThreatPolicyResource{}
)

// NewThreatPolicyResource is the factory registered with the provider.
func NewThreatPolicyResource() resource.Resource {
	return &ThreatPolicyResource{}
}

// ThreatPolicyResource implements upwind_threat_policy.
type ThreatPolicyResource struct {
	client *client.Client
}

// threatPolicyResourceModel maps HCL <-> Terraform state for a threat policy.
type threatPolicyResourceModel struct {
	ID             types.String               `tfsdk:"id"`
	Name           types.String               `tfsdk:"name"`
	Severity       types.String               `tfsdk:"severity"`
	SourceType     types.String               `tfsdk:"source_type"`
	IsEnabled      types.Bool                 `tfsdk:"is_enabled"`
	Metadata       *threatPolicyMetadataModel `tfsdk:"metadata"`
	ResourceScope  *threatPolicyScopeModel    `tfsdk:"resource_scope"`
	CreateTime     types.String               `tfsdk:"create_time"`
	UpdateTime     types.String               `tfsdk:"update_time"`
	CreatorID      types.String               `tfsdk:"creator_id"`
	LastModifierID types.String               `tfsdk:"last_modifier_id"`
}

// threatPolicyMetadataModel is the display metadata block.
type threatPolicyMetadataModel struct {
	DetectionTitle       types.String `tfsdk:"detection_title"`
	DetectionDescription types.String `tfsdk:"detection_description"`
}

// threatPolicyScopeModel is the optional resource_scope block. An omitted
// condition means the policy applies everywhere.
type threatPolicyScopeModel struct {
	Condition *threatPolicyConditionModel `tfsdk:"condition"`
}

// threatPolicyConditionModel is one scope-matching rule.
type threatPolicyConditionModel struct {
	Type     types.String `tfsdk:"type"`
	Field    types.String `tfsdk:"field"`
	Operator types.String `tfsdk:"operator"`
	Value    types.Set    `tfsdk:"value"`
}

func (r *ThreatPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_policy"
}

func (r *ThreatPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Upwind threat policy: a named detection rule container with a severity, a telemetry source, and an optional resource scope.",
		Attributes: map[string]schema.Attribute{
			// DRIFT DEFENSE: server-owned, Computed so it is never seen as writable.
			// The API calls this policy_id on reads; the provider exposes it as id
			// so `terraform import` and cross-resource references behave normally.
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this policy (server-generated). Maps to the API's `policy_id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Policy name.",
			},
			// DRIFT DEFENSE: read/write name asymmetry. The API accepts this value as
			// `default_severity` on write but returns it as `severity` on read. Both
			// are mapped onto this one attribute so a create followed by a refresh
			// compares equal.
			"severity": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Severity of detections raised by this policy. One of `low`, `medium`, `high`, `critical`. Sent to the API as `default_severity`, returned as `severity`.",
				Validators: []validator.String{
					stringvalidator.OneOf("low", "medium", "high", "critical"),
				},
			},
			// The bulk edit endpoint accepts no source_type, so changing it cannot be
			// expressed as an update - the policy has to be recreated.
			"source_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Telemetry source this policy evaluates. One of `cloud_logs`, `sensor`, `k8s_audit_logs`. Immutable: changing it forces replacement.",
				Validators: []validator.String{
					stringvalidator.OneOf("cloud_logs", "sensor", "k8s_audit_logs"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			// Optional+Computed with an explicit default matching the API's own
			// default, so an omitted value plans as `true` rather than as
			// "(known after apply)" on every plan.
			"is_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether this policy is enabled. Defaults to `true`.",
			},
			"metadata": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: "Display metadata shown on detections raised by this policy.",
				Attributes: map[string]schema.Attribute{
					"detection_title": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Title shown on a detection, e.g. `Privilege Escalation Attempt`.",
					},
					"detection_description": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Description shown on a detection.",
					},
				},
			},
			"resource_scope": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Limits which cloud resources this policy applies to. Omit to apply it everywhere.",
				Attributes: map[string]schema.Attribute{
					"condition": schema.SingleNestedAttribute{
						Optional:            true,
						MarkdownDescription: "A single scope-matching rule. Omit for no scope.",
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Required:            true,
								MarkdownDescription: "Condition type: `cloud_account_rule`, `cloud_account_ou_rule`, `cloud_account_organization_rule`, or `cluster_id_rule`. The spec also lists `cloud_provider_rule`, but the API rejects it for policy scopes with \"condition type(s) not allowed\". The composite `filter` type is not supported.",
								Validators: []validator.String{
									stringvalidator.OneOf("cloud_account_rule", "cloud_account_ou_rule", "cloud_account_organization_rule", "cluster_id_rule"),
								},
							},
							"field": schema.StringAttribute{
								Required:            true,
								MarkdownDescription: "Field to match against.",
							},
							"operator": schema.StringAttribute{
								Required:            true,
								MarkdownDescription: "Match operator. One of `equals`, `not_equals`, `in`, `not_in`.",
								Validators: []validator.String{
									stringvalidator.OneOf("equals", "not_equals", "in", "not_in"),
								},
							},
							// DRIFT DEFENSE: a Set, not a List - the API returns values in
							// arbitrary order, so set semantics avoid false drift from
							// reordering. Same choice as scope resource_filters.
							"value": schema.SetAttribute{
								Required:            true,
								ElementType:         types.StringType,
								MarkdownDescription: "Values to match against. Unordered (a set).",
							},
						},
					},
				},
			},
			// DRIFT DEFENSE: server-owned audit fields, only known after apply.
			//
			// None of them carries UseStateForUnknown. The bulk write endpoints return a
			// PARTIAL policy: creator_id and last_modifier_id are omitted entirely, and the
			// timestamps are re-stamped. Promising the stored value during planning would
			// make apply contradict its own plan ("Provider produced inconsistent result
			// after apply"). Left unknown during a write, which is what they actually are.
			"create_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the policy was created.",
			},
			"update_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the policy was last updated.",
			},
			"creator_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the user or client that created this policy.",
			},
			"last_modifier_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the user or client that last modified this policy.",
			},
		},
	}
}

// Configure receives the authenticated client built in the provider's Configure.
func (r *ThreatPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return // provider not yet configured (normal during early plan phases)
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

func (r *ThreatPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan threatPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope, diags := scopeToAPI(ctx, plan.ResourceScope)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	isEnabled := plan.IsEnabled.ValueBool()
	createReq := client.CreateThreatPolicyRequest{
		Name:            plan.Name.ValueString(),
		DefaultSeverity: plan.Severity.ValueString(),
		SourceType:      plan.SourceType.ValueString(),
		Metadata: client.ThreatPolicyMetadata{
			DetectionTitle:       plan.Metadata.DetectionTitle.ValueString(),
			DetectionDescription: plan.Metadata.DetectionDescription.ValueString(),
		},
		IsEnabled:     &isEnabled,
		ResourceScope: scope,
	}

	policy, err := r.client.CreateThreatPolicy(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating threat policy", err.Error())
		return
	}

	state, diags := threatPolicyToModel(ctx, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *ThreatPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state threatPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetThreatPolicy(ctx, state.ID.ValueString())
	if err != nil {
		// DRIFT DEFENSE: deleted out-of-band -> remove from state for clean recreation.
		if client.IsNotFound(err) {
			logGoneFromState(ctx, state.ID.ValueString())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading threat policy", err.Error())
		return
	}

	newState, diags := threatPolicyToModel(ctx, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *ThreatPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan threatPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope, diags := scopeToAPI(ctx, plan.ResourceScope)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	severity := plan.Severity.ValueString()
	isEnabled := plan.IsEnabled.ValueBool()
	updateReq := client.UpdateThreatPolicyRequest{
		ID:              plan.ID.ValueString(),
		Name:            &name,
		DefaultSeverity: &severity,
		IsEnabled:       &isEnabled,
		Metadata: &client.ThreatPolicyMetadata{
			DetectionTitle:       plan.Metadata.DetectionTitle.ValueString(),
			DetectionDescription: plan.Metadata.DetectionDescription.ValueString(),
		},
		// A removed resource_scope arrives as nil, which serialises to an omitted
		// field and leaves the existing scope in place rather than clearing it.
		// Send an explicit scope with a null condition so removal actually clears.
		ResourceScope: scope,
	}
	if scope == nil {
		updateReq.ResourceScope = &client.ResourceScope{Condition: nil}
	}

	policy, err := r.client.UpdateThreatPolicy(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating threat policy", err.Error())
		return
	}

	newState, diags := threatPolicyToModel(ctx, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *ThreatPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state threatPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Treat an already-gone policy as success (idempotent delete).
	if err := r.client.DeleteThreatPolicy(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error deleting threat policy", err.Error())
	}
}

// ImportState adopts an existing policy:
// `terraform import upwind_threat_policy.x policy_123` writes the id into state;
// the next Read populates the rest.
func (r *ThreatPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// --- mapping helpers (state <-> client types) ---

// scopeToAPI converts the resource_scope block into a client scope. A nil block
// or a block with no condition yields nil, meaning "no scope".
func scopeToAPI(ctx context.Context, m *threatPolicyScopeModel) (*client.ResourceScope, diag.Diagnostics) {
	var diags diag.Diagnostics
	if m == nil || m.Condition == nil {
		return nil, diags
	}

	var values []string
	diags.Append(m.Condition.Value.ElementsAs(ctx, &values, false)...)
	if diags.HasError() {
		return nil, diags
	}

	return &client.ResourceScope{Condition: &client.ScopeCondition{
		Type:     m.Condition.Type.ValueString(),
		Field:    m.Condition.Field.ValueString(),
		Operator: m.Condition.Operator.ValueString(),
		Value:    values,
	}}, diags
}

// threatPolicyToModel converts an API policy into Terraform state.
func threatPolicyToModel(ctx context.Context, p *client.ThreatPolicy) (threatPolicyResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	model := threatPolicyResourceModel{
		ID:         types.StringValue(p.PolicyID),
		Name:       types.StringValue(p.Name),
		Severity:   types.StringValue(p.Severity),
		SourceType: types.StringValue(p.SourceType),
		IsEnabled:  types.BoolValue(p.IsEnabled),
		Metadata: &threatPolicyMetadataModel{
			DetectionTitle:       types.StringValue(p.Metadata.DetectionTitle),
			DetectionDescription: types.StringValue(p.Metadata.DetectionDescription),
		},
		CreateTime:     types.StringValue(p.CreateTime),
		UpdateTime:     types.StringValue(p.UpdateTime),
		CreatorID:      types.StringValue(p.CreatorID),
		LastModifierID: types.StringValue(p.LastModifierID),
	}

	// DRIFT DEFENSE: null/empty equivalence. The API may return resource_scope as
	// an object with a null condition where the config omitted the block entirely;
	// both mean "no scope", so both map to a null block in state.
	if p.ResourceScope != nil && p.ResourceScope.Condition != nil {
		c := p.ResourceScope.Condition
		valSet, d := types.SetValueFrom(ctx, types.StringType, c.Value)
		diags.Append(d...)
		model.ResourceScope = &threatPolicyScopeModel{Condition: &threatPolicyConditionModel{
			Type:     types.StringValue(c.Type),
			Field:    types.StringValue(c.Field),
			Operator: types.StringValue(c.Operator),
			Value:    valSet,
		}}
	}

	return model, diags
}
