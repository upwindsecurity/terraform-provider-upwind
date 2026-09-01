package provider

import (
	"context"
	"fmt"
	"strings"

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

var (
	_ resource.Resource                = &PolicyRuleResource{}
	_ resource.ResourceWithConfigure   = &PolicyRuleResource{}
	_ resource.ResourceWithImportState = &PolicyRuleResource{}
)

// NewPolicyRuleResource is the factory registered with the provider.
func NewPolicyRuleResource() resource.Resource {
	return &PolicyRuleResource{}
}

// PolicyRuleResource implements upwind_threat_policy_rule.
type PolicyRuleResource struct {
	client *client.Client
}

type policyRuleResourceModel struct {
	ID                 types.String            `tfsdk:"id"`
	PolicyID           types.String            `tfsdk:"policy_id"`
	RuleDefinitionID   types.String            `tfsdk:"rule_definition_id"`
	RuleDefinitionName types.String            `tfsdk:"rule_definition_name"`
	ThreatCategory     types.String            `tfsdk:"threat_category"`
	Severity           types.String            `tfsdk:"severity"`
	IsEnabled          types.Bool              `tfsdk:"is_enabled"`
	IsSuspended        types.Bool              `tfsdk:"is_suspended"`
	Scope              *threatPolicyScopeModel `tfsdk:"scope"`
	ScopeType          types.String            `tfsdk:"scope_type"`
	CreateTime         types.String            `tfsdk:"create_time"`
	UpdateTime         types.String            `tfsdk:"update_time"`
	CreatorID          types.String            `tfsdk:"creator_id"`
	LastModifierID     types.String            `tfsdk:"last_modifier_id"`
}

func (r *PolicyRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_policy_rule"
}

func (r *PolicyRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the attachment of an Upwind threat rule definition to a threat policy, optionally overriding the policy's severity and resource scope.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this attachment (server-generated). Maps to the API's `policy_rule_id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			// Both identity halves are immutable: the bulk edit endpoint accepts
			// neither, and the rule lives under its policy's URL.
			"policy_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the threat policy this rule is attached to. Immutable: changing it forces replacement.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"rule_definition_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the rule definition to attach. Immutable: changing it forces replacement.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			// DRIFT DEFENSE: the API returns the EFFECTIVE severity, falling back to
			// the policy's when this rule sets none. Leaving this Optional-only and
			// preserving null means an unset override is not recorded as an owned
			// value, so a plan that omits it stays empty.
			//
			// Removal forces replacement because the API cannot express it. In
			// ApiEditPolicyRuleItem, severity is enum [low, medium, high, critical] with no
			// null and no empty string, and unlike its sibling scope ("Pass {} to clear the
			// scope") it documents no clear at all. An omitted field means "leave
			// unchanged", so a PATCH cannot drop the override: it would survive on the
			// server while state recorded null, and no later plan could see the divergence.
			// Recreating is the only way to reach "no override", and it is sound because
			// ApiCreatePolicyRuleItem defaults severity to the policy's when omitted.
			//
			// Only removal replaces. low -> critical stays a PATCH, which the API supports.
			"severity": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Severity override for this rule. One of `low`, `medium`, `high`, `critical`. Omit to inherit the policy's severity. Removing it replaces the rule, because the API has no way to clear an override in place.",
				Validators: []validator.String{
					stringvalidator.OneOf("low", "medium", "high", "critical"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(
						severityRemovalRequiresReplace,
						"Removing the severity override forces replacement.",
						"Removing the `severity` override forces replacement.",
					),
				},
			},
			"is_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether this rule is enabled within the policy. Defaults to `true`.",
			},
			"scope": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Resource scope override for this rule. Omit to inherit the policy's scope.",
				Attributes: map[string]schema.Attribute{
					"condition": schema.SingleNestedAttribute{
						Optional:            true,
						MarkdownDescription: "A single scope-matching rule. Omit for no scope.",
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Required:            true,
								MarkdownDescription: "Condition type. One of `cloud_account_rule`, `cloud_account_ou_rule`, `cloud_account_organization_rule`, `cloud_provider_rule`, `cluster_id_rule`. The composite `filter` type is not supported.",
								Validators: []validator.String{
									stringvalidator.OneOf("cloud_account_rule", "cloud_account_ou_rule", "cloud_account_organization_rule", "cloud_provider_rule", "cluster_id_rule"),
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
							"value": schema.SetAttribute{
								Required:            true,
								ElementType:         types.StringType,
								MarkdownDescription: "Values to match against. Unordered (a set).",
							},
						},
					},
				},
			},
			// Server-owned. scope_type is surfaced because it is the only way to see
			// whether the effective scope came from this rule or from its policy.
			"scope_type": schema.StringAttribute{
				// No UseStateForUnknown: adding or removing a rule-level scope flips
				// this, so the stored value is not a safe plan-time prediction.
				Computed:            true,
				MarkdownDescription: "Source of the effective scope. The API documents an enum of `policy_scope`, `rule_scope`, `override`, `no_scope`, but returns an empty string for a rule that overrides nothing, so treat any value other than `rule_scope` or `override` as inherited.",
			},
			"rule_definition_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Display name of the attached rule definition.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"threat_category": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Threat category inherited from the attached rule definition.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"is_suspended": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether this rule is currently suspended (silenced) by the platform.",
			},
			"create_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the attachment was created.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"update_time": schema.StringAttribute{
				// No UseStateForUnknown: this changes on every write, so promising the
				// stored value during planning makes apply contradict its own plan
				// ("Provider produced inconsistent result after apply"). Left unknown
				// during an update, which is what it actually is.
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the attachment was last updated.",
			},
			"creator_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the user or client that created this attachment.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_modifier_id": schema.StringAttribute{
				// No UseStateForUnknown: this changes on every write, so promising the
				// stored value during planning makes apply contradict its own plan
				// ("Provider produced inconsistent result after apply"). Left unknown
				// during an update, which is what it actually is.
				Computed:            true,
				MarkdownDescription: "ID of the user or client that last modified this attachment.",
			},
		},
	}
}

// severityRemovalRequiresReplace reports whether a severity change is a removal:
// the practitioner had an override and deleted it from the config. Only that
// direction needs a replacement; see the schema comment for why.
func severityRemovalRequiresReplace(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
	resp.RequiresReplace = !req.StateValue.IsNull() && req.ConfigValue.IsNull()
}

func (r *PolicyRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *PolicyRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope, diags := scopeToAPI(ctx, plan.Scope)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	isEnabled := plan.IsEnabled.ValueBool()
	createReq := client.CreatePolicyRuleRequest{
		RuleDefinitionID: plan.RuleDefinitionID.ValueString(),
		IsEnabled:        &isEnabled,
		Scope:            scope,
	}
	// Only send severity when the practitioner set one: omitting it is what makes
	// the rule inherit the policy's severity.
	if !plan.Severity.IsNull() {
		sev := plan.Severity.ValueString()
		createReq.Severity = &sev
	}

	pr, err := r.client.CreatePolicyRule(ctx, plan.PolicyID.ValueString(), createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy rule", err.Error())
		return
	}

	// DRIFT DEFENSE: the bulk write endpoints return a PARTIAL policy rule -
	// update_time and scope_type come back empty, while a GET returns them
	// populated. Writing the partial object into state breaks Terraform's
	// plan/apply contract on the next update: UseStateForUnknown promises the
	// stored value during planning, and apply then delivers "".
	//
	// So the write response is not trusted as state. One GET makes the write path
	// produce exactly what the read path would, which is the property the whole
	// resource depends on.
	pr, err = r.client.GetPolicyRule(ctx, plan.PolicyID.ValueString(), pr.PolicyRuleID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy rule back after write", err.Error())
		return
	}

	state, diags := policyRuleToModel(ctx, pr, plan.PolicyID, plan.Severity)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *PolicyRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pr, err := r.client.GetPolicyRule(ctx, state.PolicyID.ValueString(), state.ID.ValueString())
	if err != nil {
		// DRIFT DEFENSE: deleted out-of-band -> remove from state for clean recreation.
		if client.IsNotFound(err) {
			logGoneFromState(ctx, state.ID.ValueString())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading policy rule", err.Error())
		return
	}

	newState, diags := policyRuleToModel(ctx, pr, state.PolicyID, state.Severity)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *PolicyRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope, diags := scopeToAPI(ctx, plan.Scope)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	isEnabled := plan.IsEnabled.ValueBool()
	updateReq := client.UpdatePolicyRuleRequest{
		ID:        plan.ID.ValueString(),
		IsEnabled: &isEnabled,
		// A removed scope block must clear the override rather than be omitted,
		// which the API would read as "leave it alone". Same reasoning as the
		// threat policy resource.
		Scope: scope,
	}
	if scope == nil {
		updateReq.Scope = &client.ResourceScope{Condition: nil}
	}
	if !plan.Severity.IsNull() {
		sev := plan.Severity.ValueString()
		updateReq.Severity = &sev
	}

	pr, err := r.client.UpdatePolicyRule(ctx, plan.PolicyID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating policy rule", err.Error())
		return
	}

	// DRIFT DEFENSE: the bulk write endpoints return a PARTIAL policy rule -
	// update_time and scope_type come back empty, while a GET returns them
	// populated. Writing the partial object into state breaks Terraform's
	// plan/apply contract on the next update: UseStateForUnknown promises the
	// stored value during planning, and apply then delivers "".
	//
	// So the write response is not trusted as state. One GET makes the write path
	// produce exactly what the read path would, which is the property the whole
	// resource depends on.
	pr, err = r.client.GetPolicyRule(ctx, plan.PolicyID.ValueString(), pr.PolicyRuleID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy rule back after write", err.Error())
		return
	}

	newState, diags := policyRuleToModel(ctx, pr, plan.PolicyID, plan.Severity)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *PolicyRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Treat an already-detached rule as success (idempotent delete).
	err := r.client.DeletePolicyRule(ctx, state.PolicyID.ValueString(), state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error deleting policy rule", err.Error())
	}
}

// ImportState adopts an existing attachment. A policy rule is identified by two
// ids, so the import address is "<policy-id>/<policy-rule-id>", e.g.
// `terraform import upwind_threat_policy_rule.x policy_1/rule_2`.
func (r *PolicyRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	policyID, ruleID, ok := strings.Cut(req.ID, "/")
	if !ok || policyID == "" || ruleID == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("expected \"<policy-id>/<policy-rule-id>\", got %q", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_id"), policyID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), ruleID)...)
}

// --- mapping helpers ---

// policyRuleToModel converts an API policy rule into Terraform state.
//
// priorSeverity carries what the practitioner configured, because the API's
// severity field is the EFFECTIVE value: a rule with no override reads back the
// policy's severity, which would look like drift against an empty config.
func policyRuleToModel(ctx context.Context, pr *client.PolicyRule, policyID, priorSeverity types.String) (policyRuleResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	model := policyRuleResourceModel{
		ID:                 types.StringValue(pr.PolicyRuleID),
		PolicyID:           policyID,
		RuleDefinitionID:   types.StringValue(pr.RuleDefinitionID),
		RuleDefinitionName: types.StringValue(pr.RuleDefinitionName),
		ThreatCategory:     types.StringValue(pr.ThreatCategory),
		IsEnabled:          types.BoolValue(pr.IsEnabled),
		IsSuspended:        types.BoolValue(pr.IsSuspended),
		ScopeType:          types.StringValue(pr.ScopeType),
		CreateTime:         types.StringValue(pr.CreateTime),
		UpdateTime:         types.StringValue(pr.UpdateTime),
		CreatorID:          types.StringValue(pr.CreatorID),
		LastModifierID:     types.StringValue(pr.LastModifierID),
	}
	// The API always reports a policy_id; prefer it, and fall back to what we were
	// given (import sets it before the first read).
	if pr.PolicyID != "" {
		model.PolicyID = types.StringValue(pr.PolicyID)
	}

	// DRIFT DEFENSE: severity is effective, not owned. Keep it null unless the
	// practitioner actually set an override.
	if priorSeverity.IsNull() {
		model.Severity = types.StringNull()
	} else {
		model.Severity = types.StringValue(pr.Severity)
	}

	// DRIFT DEFENSE: scope is effective too. scope_type says where it came from,
	// so only record a scope this rule actually owns. An inherited policy_scope
	// would otherwise appear as a rule-level block the config never wrote.
	ownsScope := pr.ScopeType == "rule_scope" || pr.ScopeType == "override"
	if ownsScope && pr.Scope != nil && pr.Scope.Condition != nil {
		c := pr.Scope.Condition
		valSet, d := types.SetValueFrom(ctx, types.StringType, c.Value)
		diags.Append(d...)
		model.Scope = &threatPolicyScopeModel{Condition: &threatPolicyConditionModel{
			Type:     types.StringValue(c.Type),
			Field:    types.StringValue(c.Field),
			Operator: types.StringValue(c.Operator),
			Value:    valSet,
		}}
	}

	return model, diags
}
