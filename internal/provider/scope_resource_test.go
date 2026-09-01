package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// TestScopeToModel_DescriptionNullEmpty verifies the null/empty drift defense:
// an API-empty description stays null when the prior value was null, but a real
// value is always carried through.
func TestScopeToModel_DescriptionNullEmpty(t *testing.T) {
	ctx := context.Background()
	base := &client.Scope{
		ID:   "scope_1",
		Name: "s",
		ResourceFilters: []client.ResourceFilter{
			{Attribute: "a", Operator: "eq", Values: []string{"b"}},
		},
	}

	t.Run("empty + prior null stays null", func(t *testing.T) {
		base.Description = ""
		m, diags := scopeToModel(ctx, base, types.StringNull())
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if !m.Description.IsNull() {
			t.Errorf("expected null description, got %q", m.Description.ValueString())
		}
	})

	t.Run("non-empty is carried through", func(t *testing.T) {
		base.Description = "real"
		m, diags := scopeToModel(ctx, base, types.StringNull())
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if m.Description.ValueString() != "real" {
			t.Errorf("expected %q, got %q", "real", m.Description.ValueString())
		}
	})
}

// TestScopeToModel_FiltersRoundTrip verifies filters map into a set correctly.
func TestScopeToModel_FiltersRoundTrip(t *testing.T) {
	ctx := context.Background()
	scope := &client.Scope{
		ID:   "scope_1",
		Name: "s",
		ResourceFilters: []client.ResourceFilter{
			{Attribute: "cloud_provider", Operator: "eq", Values: []string{"aws", "gcp"}},
		},
	}
	m, diags := scopeToModel(ctx, scope, types.StringNull())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if m.ResourceFilters.IsNull() || len(m.ResourceFilters.Elements()) != 1 {
		t.Errorf("expected 1 filter element, got %v", m.ResourceFilters)
	}
}
