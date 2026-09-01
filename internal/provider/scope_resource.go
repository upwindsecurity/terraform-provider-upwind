package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// Interface checks: full resource, receives the client, supports `terraform import`.
var (
	_ resource.Resource                = &ScopeResource{}
	_ resource.ResourceWithConfigure   = &ScopeResource{}
	_ resource.ResourceWithImportState = &ScopeResource{}
)

// NewScopeResource is the factory registered with the provider.
func NewScopeResource() resource.Resource {
	return &ScopeResource{}
}

// ScopeResource implements upwind_access_scope.
type ScopeResource struct {
	client *client.Client
}

// scopeResourceModel maps HCL <-> Terraform state for a scope.
type scopeResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	ResourceFilters types.Set    `tfsdk:"resource_filters"` // set of scopeFilterModel
	CreateTime      types.String `tfsdk:"create_time"`
	UpdateTime      types.String `tfsdk:"update_time"`
	CreatorID       types.String `tfsdk:"creator_id"`
}

// scopeFilterModel is one entry in resource_filters.
type scopeFilterModel struct {
	Attribute types.String `tfsdk:"attribute"`
	Operator  types.String `tfsdk:"operator"`
	Values    types.Set    `tfsdk:"values"` // set of string
}

// scopeFilterObjectType describes a filter element, needed to rebuild the set
// from API data.
var scopeFilterObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"attribute": types.StringType,
		"operator":  types.StringType,
		"values":    types.SetType{ElemType: types.StringType},
	},
}

func (r *ScopeResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_scope"
}

func (r *ScopeResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Upwind access-management scope: a named filter defining a slice of resources.",
		Attributes: map[string]schema.Attribute{
			// DRIFT DEFENSE: server-owned, marked Computed so they're never seen as writable.
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this scope (server-generated).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Scope name.",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Scope description.",
			},
			// DRIFT DEFENSE: a Set, not a List - the API returns filters in arbitrary
			// order, so set semantics avoid false drift from reordering.
			"resource_filters": schema.SetNestedAttribute{
				Required:            true,
				MarkdownDescription: "Filters defining which resources fall in this scope. Unordered (a set).",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"attribute": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Resource attribute the filter applies to.",
						},
						"operator": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Filter operator applied to `values`. `in` matches resources whose `attribute` equals any of the given values.",
						},
						// DRIFT DEFENSE: values is also a Set (order-insensitive).
						"values": schema.SetAttribute{
							Required:            true,
							ElementType:         types.StringType,
							MarkdownDescription: "Values to match against. Unordered (a set).",
						},
					},
				},
			},
			// DRIFT DEFENSE: like id, these are server-owned and only known after
			// apply. UseStateForUnknown reuses the stored value during planning so
			// they don't show as (known after apply) on every plan when unchanged.
			"create_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the scope was created.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"update_time": schema.StringAttribute{
				// No UseStateForUnknown: this changes on every write, so promising the
				// stored value during planning makes apply contradict its own plan
				// ("Provider produced inconsistent result after apply"). Left unknown
				// during an update, which is what it actually is.
				Computed:            true,
				MarkdownDescription: "ISO8601 timestamp when the scope was last updated.",
			},
			"creator_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the user who created this scope.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// Configure receives the authenticated client built in the provider's Configure.
func (r *ScopeResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ScopeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scopeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters, diags := filtersToAPI(ctx, plan.ResourceFilters)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := client.CreateScopeRequest{
		Name:            plan.Name.ValueString(),
		ResourceFilters: filters,
	}
	if !plan.Description.IsNull() {
		createReq.Description = plan.Description.ValueString()
	}

	scope, err := r.client.CreateScope(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating scope", err.Error())
		return
	}

	state, diags := scopeToModel(ctx, scope, plan.Description)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *ScopeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scopeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope, err := r.client.GetScope(ctx, state.ID.ValueString())
	if err != nil {
		// DRIFT DEFENSE: deleted out-of-band -> remove from state for clean recreation.
		if client.IsNotFound(err) {
			logGoneFromState(ctx, state.ID.ValueString())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading scope", err.Error())
		return
	}

	newState, diags := scopeToModel(ctx, scope, state.Description)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *ScopeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan scopeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var state scopeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters, diags := filtersToAPI(ctx, plan.ResourceFilters)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	updateReq := client.UpdateScopeRequest{
		Name:            &name,
		ResourceFilters: filters,
	}
	// Three cases for description on update:
	//   plan set        -> send the new value.
	//   plan null, prior set -> user removed it: send "" so the API clears it
	//                          (a removed optional and a never-set one both arrive
	//                          as null, so prior state is what distinguishes them).
	//   plan null, prior null -> never set: omit, leave the API untouched.
	if !plan.Description.IsNull() {
		desc := plan.Description.ValueString()
		updateReq.Description = &desc
	} else if !state.Description.IsNull() {
		empty := ""
		updateReq.Description = &empty
	}

	scope, err := r.client.UpdateScope(ctx, plan.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating scope", err.Error())
		return
	}

	newState, diags := scopeToModel(ctx, scope, plan.Description)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *ScopeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state scopeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Treat an already-gone scope as success (idempotent delete).
	if err := r.client.DeleteScope(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error deleting scope", err.Error())
	}
}

// ImportState adopts an existing scope: `terraform import upwind_access_scope.x scope_123`
// writes the id into state; the next Read populates the rest.
func (r *ScopeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// --- mapping helpers (state <-> client types) ---

// filtersToAPI converts the resource_filters set into client filter structs.
func filtersToAPI(ctx context.Context, set types.Set) ([]client.ResourceFilter, diag.Diagnostics) {
	var diags diag.Diagnostics
	var models []scopeFilterModel
	diags.Append(set.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return nil, diags
	}

	filters := make([]client.ResourceFilter, 0, len(models))
	for _, m := range models {
		var values []string
		diags.Append(m.Values.ElementsAs(ctx, &values, false)...)
		if diags.HasError() {
			return nil, diags
		}
		filters = append(filters, client.ResourceFilter{
			Attribute: m.Attribute.ValueString(),
			Operator:  m.Operator.ValueString(),
			Values:    values,
		})
	}
	return filters, diags
}

// scopeToModel converts an API scope into Terraform state. priorDescription lets
// us preserve null vs "" so an unset description doesn't show as drift.
func scopeToModel(ctx context.Context, scope *client.Scope, priorDescription types.String) (scopeResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	model := scopeResourceModel{
		ID:         types.StringValue(scope.ID),
		Name:       types.StringValue(scope.Name),
		CreateTime: types.StringValue(scope.CreateTime),
		UpdateTime: types.StringValue(scope.UpdateTime),
		CreatorID:  types.StringValue(scope.CreatorID),
	}

	// DRIFT DEFENSE: null/empty equivalence for the optional description.
	if scope.Description == "" && priorDescription.IsNull() {
		model.Description = types.StringNull()
	} else {
		model.Description = types.StringValue(scope.Description)
	}

	filterModels := make([]scopeFilterModel, 0, len(scope.ResourceFilters))
	for _, f := range scope.ResourceFilters {
		valSet, d := types.SetValueFrom(ctx, types.StringType, f.Values)
		diags.Append(d...)
		filterModels = append(filterModels, scopeFilterModel{
			Attribute: types.StringValue(f.Attribute),
			Operator:  types.StringValue(f.Operator),
			Values:    valSet,
		})
	}
	filterSet, d := types.SetValueFrom(ctx, scopeFilterObjectType, filterModels)
	diags.Append(d...)
	model.ResourceFilters = filterSet

	return model, diags
}
