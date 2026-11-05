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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

var (
	_ resource.Resource                = &PolicyRuleResource{}
	_ resource.ResourceWithConfigure   = &PolicyRuleResource{}
	_ resource.ResourceWithImportState = &PolicyRuleResource{}
	// The framework finds ModifyPlan by type assertion, so a drifted signature would
	// simply stop the reset and re-assert from running, silently.
	_ resource.ResourceWithModifyPlan = &PolicyRuleResource{}
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
			// DRIFT DEFENSE: the API returns the EFFECTIVE enabled state, which is
			// capped by the policy's - a rule inside a disabled policy reads back
			// false however it was written.
			//
			// So no Default. A static default is a plan-time promise the framework
			// then enforces against the apply result, and attaching a rule to a
			// disabled policy broke that promise: planned true, read back false,
			// "Provider produced inconsistent result after apply". Worse, the default
			// re-asserts itself on every later plan (TransformDefaults consults the
			// config, never prior state), so the resource could never converge.
			//
			// Optional+Computed with no default leaves it unknown during a create,
			// which absorbs whatever the server reports. An explicit is_enabled = true
			// under a disabled policy still fails the apply - not because the API
			// rejects the write (it accepts it) but because the capped read disagrees
			// with what the config promised.
			"is_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				// One paragraph, as severity is. A blank line here breaks the Registry's
				// Optional bullet list in two and detaches the text from this attribute.
				MarkdownDescription: "Whether this rule is enabled within the policy. The platform reports " +
					"the effective state, so a rule inside a policy with `is_enabled = false` reads back as " +
					"`false` whatever is set here - enable the policy to enable its rules. Omit to follow the " +
					"policy; removing it after setting it resets the rule to the API default of `true` " +
					"(enabled) in place, with no replacement. Importing a rule whose configuration sets " +
					"this attribute plans one update, which re-asserts the configured value.",
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

// isEnabledOwnedKey records, in private state, whether the practitioner set
// is_enabled. State cannot answer that: is_enabled is Optional+Computed, so it always
// holds the effective value and a never-set attribute is indistinguishable from a
// removed one.
const isEnabledOwnedKey = "is_enabled_owned"

// isEnabledWasRemoved reports a removal: the practitioner had is_enabled in the
// config, this rule owns the value on the server, and the line is now gone.
//
// State cannot answer this on its own. is_enabled is Optional+Computed, so it always
// holds the effective value and a never-set attribute looks exactly like a removed
// one; the API offers no discriminator either (a GET returns no default_values for
// it). Hence the private-state record.
func isEnabledWasRemoved(hasState, hasPlan, configSet, owned bool) bool {
	return hasState && hasPlan && !configSet && owned
}

// isEnabledWasNeverAsserted reports a value the config states but the API was never
// told: the practitioner wrote is_enabled, and no write of ours has claimed it.
//
// The read cannot reveal this. Under a disabled policy every rule reports false
// whatever it holds, so is_enabled = false matches state exactly, nothing is planned
// and the rule keeps the API default of true - until the policy is enabled and a
// detection the practitioner declared off goes live.
//
// Rules with no private data at all land here too, which is deliberate: one apply
// after upgrading re-asserts a configured is_enabled that an older version may never
// have sent.
func isEnabledWasNeverAsserted(hasState, hasPlan, configSet, owned bool) bool {
	return hasState && hasPlan && configSet && !owned
}

// ModifyPlan turns a removed is_enabled into a diff, so Update runs and can reset the
// rule to the API default.
//
// Resource level rather than an attribute plan modifier, and that is not a style
// choice. The framework marks write-derived Computed attributes unknown only when the
// PROPOSED plan already differs from prior state, and that pass runs BEFORE attribute
// modifiers. A removal is invisible at that point - for an Optional+Computed
// attribute a null config means "keep prior state" - so a modifier that creates the
// diff afterwards leaves update_time and last_modifier_id pinned to their stale
// values and the apply dies with "inconsistent result after apply".
//
// Rules written before isEnabledOwnedKey existed carry no private data and are left
// alone, so upgrading changes no plans; one holding an unwanted false picks the reset
// up as soon as its configuration changes for any other reason.
func (r *PolicyRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	owned := isEnabledOwnedRecord(ctx, req.Private, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var configIsEnabled types.Bool
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("is_enabled"), &configIsEnabled)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	hasState, hasPlan := !req.State.Raw.IsNull(), !req.Plan.Raw.IsNull()
	configSet := !configIsEnabled.IsNull()

	switch {
	case isEnabledWasRemoved(hasState, hasPlan, configSet, owned):
		// Unknown, not a literal true: the reset restores the API default, which the
		// policy caps on read, so planning true under a disabled policy would
		// contradict the apply.
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("is_enabled"), types.BoolUnknown())...)
	case isEnabledWasNeverAsserted(hasState, hasPlan, configSet, owned):
		// is_enabled is deliberately left alone here. Terraform rejects a planned
		// value that differs from a known config value, so the diff has to be carried
		// by the write-derived attributes below instead - which is enough, because any
		// non-empty plan calls ApplyResourceChange and Update then sends the value.
	default:
		return
	}

	// Both paths write, and these two move on every write - the same two the schema
	// denies UseStateForUnknown for. Marking them is what makes the plan non-empty in
	// the assert case; in the reset case it keeps apply from contradicting its plan.
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("update_time"), types.StringUnknown())...)
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("last_modifier_id"), types.StringUnknown())...)
}

// isEnabledOwnedRecord reads the ownership flag back. Absent data - a rule written
// before this key existed, or imported - reads as NOT owned, so nothing is reset
// behind the practitioner's back. A nil *privatestate.ProviderData is safe: GetKey
// handles a nil receiver and returns no data.
func isEnabledOwnedRecord(ctx context.Context, private interface {
	GetKey(context.Context, string) ([]byte, diag.Diagnostics)
}, diags *diag.Diagnostics) bool {
	v, d := private.GetKey(ctx, isEnabledOwnedKey)
	diags.Append(d...)
	return string(v) == "true"
}

// recordIsEnabledOwned stores whether this write set is_enabled, for the plan
// modifier above. Values must be valid JSON.
func recordIsEnabledOwned(ctx context.Context, private interface {
	SetKey(context.Context, string, []byte) diag.Diagnostics
}, owned bool) diag.Diagnostics {
	v := []byte("false")
	if owned {
		v = []byte("true")
	}
	return private.SetKey(ctx, isEnabledOwnedKey, v)
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

// isEnabledFromConfig returns the practitioner's is_enabled, or nil when they did
// not write one.
//
// It reads the CONFIG on purpose. is_enabled is Optional+Computed, so the plan holds
// unknown on a create and the prior state on an update - neither of which answers
// "did the practitioner set this?". Sending a value derived from the plan is what made
// an omitted attribute become an owned `false` the platform then refused to change.
//
// nil means "send nothing", which is what lets the rule inherit its policy's state.
func isEnabledFromConfig(ctx context.Context, config tfsdk.Config, diags *diag.Diagnostics) *bool {
	var isEnabled types.Bool
	diags.Append(config.GetAttribute(ctx, path.Root("is_enabled"), &isEnabled)...)
	if diags.HasError() || isEnabled.IsNull() || isEnabled.IsUnknown() {
		return nil
	}
	v := isEnabled.ValueBool()
	return &v
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

	createReq := client.CreatePolicyRuleRequest{
		RuleDefinitionID: plan.RuleDefinitionID.ValueString(),
		Scope:            scope,
	}
	// Only send severity when the practitioner set one: omitting it is what makes
	// the rule inherit the policy's severity.
	if !plan.Severity.IsNull() {
		sev := plan.Severity.ValueString()
		createReq.Severity = &sev
	}
	// CONFIG, not plan. is_enabled is Optional+Computed, so the plan holds unknown
	// here and ValueBool() renders that as false - which made every omitted value an
	// owned `false` the policy could never override.
	enabled := isEnabledFromConfig(ctx, req.Config, &resp.Diagnostics)
	if enabled != nil {
		createReq.IsEnabled = enabled
	}
	resp.Diagnostics.Append(recordIsEnabledOwned(ctx, resp.Private, enabled != nil)...)

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
	pr, err = r.client.GetPolicyRuleAfterWrite(ctx, plan.PolicyID.ValueString(), pr.PolicyRuleID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy rule back after write", err.Error())
		return
	}

	// Null: the planned is_enabled is unknown on a create, so take the server's.
	state, diags := policyRuleToModel(ctx, pr, plan.PolicyID, plan.Severity, types.BoolNull())
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

	// Null: a refresh is where the server's effective is_enabled should land.
	newState, diags := policyRuleToModel(ctx, pr, state.PolicyID, state.Severity, types.BoolNull())
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

	updateReq := client.UpdatePolicyRuleRequest{
		ID: plan.ID.ValueString(),
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
	// Config, not plan - see Create. Here the plan holds the PRIOR STATE, so sending
	// it re-asserts a value the practitioner never wrote.
	//
	// A REMOVAL sends the API default rather than nothing, because the edit endpoint
	// leaves an omitted field alone and the rule would keep the value it owns.
	// Verified against the live API - a rule PATCHed back to true is indistinguishable
	// from one created without the field, through a policy disable/enable cycle.
	//
	// The ownership record is the discriminator, and only it will do. An omitted
	// is_enabled does NOT mean "reset": a rule can legitimately own false while the
	// config says nothing - every rule written by v0.1.1 does, and so does one an
	// operator disabled in the console. Resetting on every such update would enable a
	// detection during an unrelated severity edit, with nothing in the plan to say so.
	//
	// The PLAN cannot answer this. Terraform marks every Computed attribute with a
	// null config value unknown as soon as anything else in the resource changes, so
	// plan.IsEnabled is unknown on a plain severity edit just as it is on a removal.
	// Only private state knows whether this provider ever wrote the value.
	owned := isEnabledOwnedRecord(ctx, req.Private, &resp.Diagnostics)
	enabled := isEnabledFromConfig(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	switch {
	case enabled != nil:
		updateReq.IsEnabled = enabled
	case owned:
		reset := true
		updateReq.IsEnabled = &reset
	}
	resp.Diagnostics.Append(recordIsEnabledOwned(ctx, resp.Private, enabled != nil)...)

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
	pr, err = r.client.GetPolicyRuleAfterWrite(ctx, plan.PolicyID.ValueString(), pr.PolicyRuleID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy rule back after write", err.Error())
		return
	}

	// Omitted is_enabled: the plan holds the prior state and the read-back may hold a
	// newly-effective value. Keep the plan, or Terraform fails the apply.
	plannedIsEnabled := types.BoolNull()
	if enabled == nil {
		plannedIsEnabled = plan.IsEnabled
	}
	newState, diags := policyRuleToModel(ctx, pr, plan.PolicyID, plan.Severity, plannedIsEnabled)
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
//
// plannedIsEnabled is the same idea, set ONLY when the practitioner omitted the
// attribute on an update: a read-back in an apply that also enabled the parent
// returns the new value while the plan promised the old one, which Terraform rejects
// as "inconsistent result after apply".
//
// Null means take the server's value - right on a create, and right when the
// practitioner DID set it, where a disagreement must still error.
func policyRuleToModel(ctx context.Context, pr *client.PolicyRule, policyID, priorSeverity types.String, plannedIsEnabled types.Bool) (policyRuleResourceModel, diag.Diagnostics) {
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

	// See the doc comment: only an omitted-on-update is_enabled is pinned.
	if !plannedIsEnabled.IsNull() && !plannedIsEnabled.IsUnknown() {
		model.IsEnabled = plannedIsEnabled
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
