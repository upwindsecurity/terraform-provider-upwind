package provider

import (
	"context"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// TestResourceSchemas validates every registered resource schema. Schema
// construction errors otherwise surface only at apply time against a real tenant.
func TestResourceSchemas(t *testing.T) {
	ctx := context.Background()
	for name, factory := range map[string]func() fwresource.Resource{
		"access_scope":           NewScopeResource,
		"threat_policy":          NewThreatPolicyResource,
		"threat_policy_rule":     NewPolicyRuleResource,
		"threat_rule_definition": NewRuleDefinitionResource,
		"malware_indicator":      NewMalwareIndicatorResource,
	} {
		t.Run(name, func(t *testing.T) {
			resp := &fwresource.SchemaResponse{}
			factory().Schema(ctx, fwresource.SchemaRequest{}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
			}
			if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
				t.Fatalf("schema implementation invalid: %v", diags)
			}
		})
	}
}

// TestRuleDefinitionToModel_MitreNullEmpty pins the null/empty drift defense for
// the optional MITRE fields: unset ones must stay null rather than flipping to "".
func TestRuleDefinitionToModel_MitreNullEmpty(t *testing.T) {
	rd := &client.RuleDefinition{
		RuleDefinitionID: "rd_1", Name: "n", Engine: "rego",
		Metadata: client.RuleDefinitionMeta{DetectionTitle: "T", DetectionDescription: "D"},
	}

	t.Run("unset stays null", func(t *testing.T) {
		m := ruleDefinitionToModel(rd, &ruleDefinitionMetaModel{
			MitreTacticCode: types.StringNull(),
		})
		if !m.Metadata.MitreTacticCode.IsNull() {
			t.Errorf("expected null mitre_tactic_code, got %q", m.Metadata.MitreTacticCode.ValueString())
		}
	})

	t.Run("set is carried through", func(t *testing.T) {
		rd.Metadata.MitreTacticCode = "TA0001"
		m := ruleDefinitionToModel(rd, &ruleDefinitionMetaModel{
			MitreTacticCode: types.StringValue("TA0001"),
		})
		if got := m.Metadata.MitreTacticCode.ValueString(); got != "TA0001" {
			t.Errorf("mitre_tactic_code: got %q, want %q", got, "TA0001")
		}
	})
}

// TestPolicyRuleToModel_EffectiveValues is the important one for policy rules.
// The API returns EFFECTIVE severity and scope: a rule that overrides neither
// still reads back the policy's values. Recording those as rule-owned produces
// permanent drift against a config that sets neither.
func TestPolicyRuleToModel_EffectiveValues(t *testing.T) {
	ctx := context.Background()
	policyID := types.StringValue("policy_1")

	// A rule inheriting the policy's scope and severity.
	inherited := &client.PolicyRule{
		PolicyRuleID: "pr_1", PolicyID: "policy_1", RuleDefinitionID: "rd_1",
		Severity:  "critical",     // inherited from the policy
		ScopeType: "policy_scope", // says so explicitly
		Scope: &client.ResourceScope{Condition: &client.ScopeCondition{
			Type: "cloud_provider_rule", Field: "cloud_provider",
			Operator: "in", Value: []string{"aws"},
		}},
	}

	t.Run("inherited severity is not recorded", func(t *testing.T) {
		m, diags := policyRuleToModel(ctx, inherited, policyID, types.StringNull())
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if !m.Severity.IsNull() {
			t.Errorf("expected null severity for an inherited value, got %q", m.Severity.ValueString())
		}
	})

	t.Run("inherited scope is not recorded", func(t *testing.T) {
		m, diags := policyRuleToModel(ctx, inherited, policyID, types.StringNull())
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if m.Scope != nil {
			t.Errorf("expected null scope for scope_type=policy_scope, got %+v", m.Scope)
		}
		if got := m.ScopeType.ValueString(); got != "policy_scope" {
			t.Errorf("scope_type must still be surfaced, got %q", got)
		}
	})

	t.Run("owned severity and scope are recorded", func(t *testing.T) {
		owned := *inherited
		owned.ScopeType = "rule_scope"
		m, diags := policyRuleToModel(ctx, &owned, policyID, types.StringValue("critical"))
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if m.Severity.ValueString() != "critical" {
			t.Errorf("severity: got %q, want %q", m.Severity.ValueString(), "critical")
		}
		if m.Scope == nil || m.Scope.Condition == nil {
			t.Fatalf("expected an owned scope for scope_type=rule_scope, got %+v", m.Scope)
		}
	})
}

// TestMalwareIndicatorToModel_IDMirrorsHash pins the identity choice: the API
// generates no id, so id must mirror hash for import to work with a bare hash.
func TestMalwareIndicatorToModel_IDMirrorsHash(t *testing.T) {
	m := malwareIndicatorToModel(&client.MalwareIndicator{
		Hash: "abc123", HashType: "sha1", Action: "allow",
	}, types.StringNull())

	if m.ID.ValueString() != "abc123" {
		t.Errorf("id: got %q, want it to mirror hash %q", m.ID.ValueString(), "abc123")
	}
	if !m.Reason.IsNull() {
		t.Errorf("expected null reason when unset, got %q", m.Reason.ValueString())
	}
}

// TestDataSourceSchemas validates every registered data source schema, the same
// guard TestResourceSchemas provides for resources.
func TestDataSourceSchemas(t *testing.T) {
	ctx := context.Background()
	for name, factory := range map[string]func() fwdatasource.DataSource{
		"threat_story":                NewStoryDataSource,
		"threat_stories":              NewStoriesDataSource,
		"threat_skill":                NewSkillDataSource,
		"threat_skills":               NewSkillsDataSource,
		"configuration_finding":       NewConfigurationFindingDataSource,
		"configuration_findings":      NewConfigurationFindingsDataSource,
		"configuration_asset_example": NewConfigurationAssetExampleDataSource,
	} {
		t.Run(name, func(t *testing.T) {
			resp := &fwdatasource.SchemaResponse{}
			factory().Schema(ctx, fwdatasource.SchemaRequest{}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
			}
			if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
				t.Fatalf("schema implementation invalid: %v", diags)
			}
		})
	}
}

// TestProviderRegistersEverything guards against writing a resource or data
// source and forgetting to register it, which makes it silently unavailable.
func TestProviderRegistersEverything(t *testing.T) {
	ctx := context.Background()
	p := New("test")()

	if got, want := len(p.Resources(ctx)), 5; got != want {
		t.Errorf("registered resources: got %d, want %d", got, want)
	}
	if got, want := len(p.DataSources(ctx)), 7; got != want {
		t.Errorf("registered data sources: got %d, want %d", got, want)
	}
}
