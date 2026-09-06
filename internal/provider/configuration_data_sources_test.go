package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/upwindsecurity/terraform-provider-upwind/internal/client"
)

// The nested framework/rule/resource objects are the whole value of a finding: an
// id and a severity alone say nothing actionable. This guards the mapping between
// the API's snake_case fields and the Terraform model, where a mistyped tfsdk tag
// is otherwise only caught at apply time.
func TestConfigurationFindingToModel_NestedObjects(t *testing.T) {
	model, diags := configurationFindingToModel(context.Background(), client.ConfigurationFinding{
		ID:             "cf_1",
		Title:          "Bucket is public",
		Severity:       "high",
		Status:         "fail",
		RiskCategories: []string{"data_exposure", "misconfiguration"},
		Framework:      client.ConfigurationFindingFramework{ID: "fw_1", Title: "CIS AWS", Status: "enabled"},
		Rule:           client.ConfigurationFindingRule{ID: "cr_1", Remediation: "Block public access"},
		Resource:       client.ConfigurationFindingResource{Name: "my-bucket", Region: "us-west-2", UpwindAssetID: "asset_1"},
	})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.Framework == nil || model.Rule == nil || model.Resource == nil {
		t.Fatalf("nested objects must not be nil: %+v", model)
	}
	if got, want := model.Rule.Remediation, types.StringValue("Block public access"); got != want {
		t.Errorf("rule.remediation: got %v, want %v", got, want)
	}
	if got, want := model.Resource.UpwindAssetID, types.StringValue("asset_1"); got != want {
		t.Errorf("resource.upwind_asset_id: got %v, want %v", got, want)
	}
	// "enabled" as a string, not a bool - the findings shape of a framework differs
	// from the one the frameworks write endpoints use.
	if got, want := model.Framework.Status, types.StringValue("enabled"); got != want {
		t.Errorf("framework.status: got %v, want %v", got, want)
	}
	if l := len(model.RiskCategories.Elements()); l != 2 {
		t.Errorf("risk_categories: got %d elements, want 2", l)
	}
}

// A finding whose nested objects the API omitted must still produce a usable
// model rather than a nil dereference downstream.
func TestConfigurationFindingToModel_EmptyNestedObjects(t *testing.T) {
	model, diags := configurationFindingToModel(context.Background(), client.ConfigurationFinding{ID: "cf_2"})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if model.Framework == nil || model.Rule == nil || model.Resource == nil {
		t.Fatal("nested objects must be present even when the API omits them")
	}
	if !model.RiskCategories.IsNull() && len(model.RiskCategories.Elements()) != 0 {
		t.Errorf("risk_categories should be null or empty, got %v", model.RiskCategories)
	}

	// The kind-conditional fields must stay null, not "". A practitioner branching
	// on `cluster_id == null` to mean "not a Kubernetes resource" gets the wrong
	// answer if an absent field reads back as an empty string.
	for name, got := range map[string]types.String{
		"arn":        model.Resource.ARN,
		"cluster_id": model.Resource.ClusterID,
		"namespace":  model.Resource.Namespace,
	} {
		if !got.IsNull() {
			t.Errorf("%s: got %q, want null when the API omits it", name, got.ValueString())
		}
	}
}

// A resource that does populate the conditional fields must carry them through.
func TestConfigurationFindingToModel_ConditionalFieldsWhenPresent(t *testing.T) {
	model, diags := configurationFindingToModel(context.Background(), client.ConfigurationFinding{
		ID: "cf_3",
		Resource: client.ConfigurationFindingResource{
			ARN:       "arn:aws:s3:::bucket",
			ClusterID: "cluster_1",
			Namespace: "kube-system",
		},
	})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if got, want := model.Resource.ARN, types.StringValue("arn:aws:s3:::bucket"); got != want {
		t.Errorf("arn: got %v, want %v", got, want)
	}
	if got, want := model.Resource.Namespace, types.StringValue("kube-system"); got != want {
		t.Errorf("namespace: got %v, want %v", got, want)
	}
}

// The error message must distinguish "nothing of this kind anywhere" from
// "nothing of this kind in the account you asked about" - otherwise a scoped
// lookup that finds nothing reads as the kind being invalid.
func TestAccountSuffix(t *testing.T) {
	for name, tc := range map[string]struct {
		in   types.String
		want string
	}{
		"null":  {types.StringNull(), ""},
		"empty": {types.StringValue(""), ""},
		"set":   {types.StringValue("12345"), ` in cloud account "12345"`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := accountSuffix(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The collection drops three prose fields to keep the Terraform state small,
// while the singular data source keeps them so nothing is unreachable. That
// split is the whole point of the two data sources differing, and a schema is
// easy to edit in one place and not the other.
func TestConfigurationFindings_CollectionOmitsProseSingularKeepsIt(t *testing.T) {
	ctx := context.Background()
	prose := map[string][]string{
		"rule":      {"description", "remediation"},
		"framework": {"description"},
	}

	nested := func(d datasource.DataSource, block string) map[string]schema.Attribute {
		t.Helper()
		resp := &datasource.SchemaResponse{}
		d.Schema(ctx, datasource.SchemaRequest{}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
		}
		attrs := resp.Schema.Attributes
		if list, ok := attrs["findings"].(schema.ListNestedAttribute); ok {
			attrs = list.NestedObject.Attributes // the collection nests each finding
		}
		return attrs[block].(schema.SingleNestedAttribute).Attributes
	}

	for block, fields := range prose {
		singular := nested(NewConfigurationFindingDataSource(), block)
		collection := nested(NewConfigurationFindingsDataSource(), block)
		for _, f := range fields {
			if _, ok := singular[f]; !ok {
				t.Errorf("upwind_configuration_finding is missing %s.%s - the full record must stay reachable", block, f)
			}
			if _, ok := collection[f]; ok {
				t.Errorf("upwind_configuration_findings still exposes %s.%s - it is persisted per finding", block, f)
			}
		}
		// The fields they do share must not drift apart.
		for name := range collection {
			if _, ok := singular[name]; !ok {
				t.Errorf("%s.%s is in the collection but not the singular data source", block, name)
			}
		}
	}
}
