package provider

import (
	"context"
	"reflect"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// TestNoUnvettedComputedDefaults pins the plan-time-promise invariant.
//
// A Computed attribute carrying a Default is a value the provider swears it
// knows before apply: the framework fills the default in during planning, then
// enforces that the post-apply value matches. If the server computes that field
// instead, apply dies with "Provider produced inconsistent result after apply"
// and the resource can never converge, because the default re-asserts itself on
// every subsequent plan.
//
// That is how upwind_threat_policy_rule.is_enabled shipped broken in v0.1.0: the
// API reports it as an EFFECTIVE value, so a rule inside a disabled policy reads
// back false while the schema had promised true.
//
// Every entry in vetted below is a deliberate decision that the PROVIDER, not the
// server, owns the value. Adding a Default to a Computed attribute fails this test
// until someone writes down why.
func TestNoUnvettedComputedDefaults(t *testing.T) {
	vetted := map[string]string{
		"threat_policy.is_enabled": "policy-level flag with no parent to inherit from; " +
			"matches the API's own default and a write round-trips unchanged",
	}

	ctx := context.Background()
	for name, factory := range map[string]func() fwresource.Resource{
		"access_scope":           NewScopeResource,
		"threat_policy":          NewThreatPolicyResource,
		"threat_policy_rule":     NewPolicyRuleResource,
		"threat_rule_definition": NewRuleDefinitionResource,
		"malware_indicator":      NewMalwareIndicatorResource,
	} {
		resp := &fwresource.SchemaResponse{}
		factory().Schema(ctx, fwresource.SchemaRequest{}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s: schema diagnostics: %v", name, resp.Diagnostics)
		}
		walkAttributes(t, name, resp.Schema.Attributes, vetted)
	}
}

// walkAttributes reports any Computed attribute with a Default that is not vetted.
//
// ponytail: recurses through SingleNestedAttribute only, the one nesting kind this
// provider uses. Add the List/Set/Map nested cases if a collection of objects ever
// gains a default.
func walkAttributes(t *testing.T, resource string, attrs map[string]schema.Attribute, vetted map[string]string) {
	t.Helper()
	for attrName, attr := range attrs {
		key := resource + "." + attrName

		// Default is an interface field (defaults.Bool, defaults.String, ...) present
		// on every concrete attribute type that supports one, so reflection reads it
		// without a type switch over all of them.
		if f := reflect.ValueOf(attr).FieldByName("Default"); f.IsValid() &&
			f.Kind() == reflect.Interface && !f.IsNil() {
			if _, ok := vetted[key]; !ok {
				t.Errorf("%s is Computed with a Default, so the provider promises its value at "+
					"plan time. If the server computes or inherits it, apply will fail with "+
					"\"inconsistent result after apply\". Drop the Default, or add %q to vetted "+
					"with the reason the provider owns it.", key, key)
			}
		}

		if nested, ok := attr.(schema.SingleNestedAttribute); ok {
			walkAttributes(t, key, nested.Attributes, vetted)
		}
	}
}
