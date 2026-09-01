package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// TestThreatPolicyToModel_SeverityMapping pins the read/write name asymmetry:
// the API returns the value as `severity`, and it must land on the `severity`
// attribute that the config writes as `default_severity`. Getting this wrong
// produces permanent drift on every plan.
func TestThreatPolicyToModel_SeverityMapping(t *testing.T) {
	m, diags := threatPolicyToModel(context.Background(), &client.ThreatPolicy{
		PolicyID: "policy_1", Name: "p", Severity: "critical", SourceType: "sensor",
	})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if m.Severity.ValueString() != "critical" {
		t.Errorf("severity: got %q, want %q", m.Severity.ValueString(), "critical")
	}
	if m.ID.ValueString() != "policy_1" {
		t.Errorf("id must come from policy_id, got %q", m.ID.ValueString())
	}
}

// TestThreatPolicyToModel_ScopeNullEquivalence verifies the drift defense: a
// missing scope and a scope carrying a null condition both mean "no scope" and
// must both produce a null block, matching a config that omits it.
func TestThreatPolicyToModel_ScopeNullEquivalence(t *testing.T) {
	ctx := context.Background()

	for name, scope := range map[string]*client.ResourceScope{
		"absent":         nil,
		"null condition": {Condition: nil},
	} {
		t.Run(name, func(t *testing.T) {
			m, diags := threatPolicyToModel(ctx, &client.ThreatPolicy{
				PolicyID: "policy_1", ResourceScope: scope,
			})
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if m.ResourceScope != nil {
				t.Errorf("expected a null resource_scope, got %+v", m.ResourceScope)
			}
		})
	}

	t.Run("populated condition is carried through", func(t *testing.T) {
		m, diags := threatPolicyToModel(ctx, &client.ThreatPolicy{
			PolicyID: "policy_1",
			ResourceScope: &client.ResourceScope{Condition: &client.ScopeCondition{
				Type: "cloud_provider_rule", Field: "cloud_provider",
				Operator: "in", Value: []string{"aws"},
			}},
		})
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if m.ResourceScope == nil || m.ResourceScope.Condition == nil {
			t.Fatalf("expected a condition, got %+v", m.ResourceScope)
		}
		if got := m.ResourceScope.Condition.Type.ValueString(); got != "cloud_provider_rule" {
			t.Errorf("type: got %q", got)
		}
	})
}

// TestScopeToAPI_RemovedScopeIsNil confirms an omitted or condition-less block
// converts to nil, which Update turns into an explicit null-condition scope so
// removing the block actually clears the scope server-side.
func TestScopeToAPI_RemovedScopeIsNil(t *testing.T) {
	ctx := context.Background()

	if got, diags := scopeToAPI(ctx, nil); got != nil || diags.HasError() {
		t.Errorf("nil block: got %+v, diags %v", got, diags)
	}
	if got, diags := scopeToAPI(ctx, &threatPolicyScopeModel{}); got != nil || diags.HasError() {
		t.Errorf("empty block: got %+v, diags %v", got, diags)
	}

	valSet, _ := types.SetValueFrom(ctx, types.StringType, []string{"aws", "gcp"})
	got, diags := scopeToAPI(ctx, &threatPolicyScopeModel{Condition: &threatPolicyConditionModel{
		Type:     types.StringValue("cloud_provider_rule"),
		Field:    types.StringValue("cloud_provider"),
		Operator: types.StringValue("in"),
		Value:    valSet,
	}})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if got == nil || got.Condition == nil || len(got.Condition.Value) != 2 {
		t.Fatalf("expected a two-value condition, got %+v", got)
	}
}
