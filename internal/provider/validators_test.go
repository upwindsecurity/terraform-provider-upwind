package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	provschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	resschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// runStringValidators feeds one value through every validator on an attribute and
// reports whether it was rejected.
func runStringValidators(t *testing.T, name string, validators []validator.String, value string) bool {
	t.Helper()
	req := validator.StringRequest{
		Path:        path.Root(name),
		ConfigValue: types.StringValue(value),
	}
	var resp validator.StringResponse
	for _, v := range validators {
		v.ValidateString(context.Background(), req, &resp)
	}
	return resp.Diagnostics.HasError()
}

// providerStringAttribute pulls one top-level attribute out of the provider schema.
func providerStringAttribute(t *testing.T, name string) provschema.StringAttribute {
	t.Helper()
	var resp fwprovider.SchemaResponse
	(&UpwindProvider{}).Schema(context.Background(), fwprovider.SchemaRequest{}, &resp)
	attr, ok := resp.Schema.Attributes[name].(provschema.StringAttribute)
	if !ok {
		t.Fatalf("provider attribute %q is not a StringAttribute", name)
	}
	return attr
}

// resourceStringAttribute pulls one top-level attribute out of a resource schema.
func resourceStringAttribute(t *testing.T, r fwresource.Resource, name string) resschema.StringAttribute {
	t.Helper()
	var resp fwresource.SchemaResponse
	r.Schema(context.Background(), fwresource.SchemaRequest{}, &resp)
	attr, ok := resp.Schema.Attributes[name].(resschema.StringAttribute)
	if !ok {
		t.Fatalf("resource attribute %q is not a StringAttribute", name)
	}
	return attr
}

// The region is the one validator that has to run before the client exists: an
// invalid value must surface as an attribute error at validate/plan time rather
// than as a client construction failure during Configure.
func TestProviderSchema_RegionValidator(t *testing.T) {
	attr := providerStringAttribute(t, "region")
	if len(attr.Validators) == 0 {
		t.Fatal("region has no validators")
	}
	for value, wantErr := range map[string]bool{
		"us": false, "eu": false, "me": false,
		"moon": true, "US": true, "": true,
	} {
		if got := runStringValidators(t, "region", attr.Validators, value); got != wantErr {
			t.Errorf("region %q: rejected=%v, want rejected=%v", value, got, wantErr)
		}
	}
}

// Spot-check that resource-level enums are wired too, using the two attributes
// whose closed sets are narrowest.
func TestMalwareIndicatorSchema_EnumValidators(t *testing.T) {
	r := NewMalwareIndicatorResource()

	hashType := resourceStringAttribute(t, r, "hash_type")
	for value, wantErr := range map[string]bool{"sha1": false, "sha256": true, "md5": true} {
		if got := runStringValidators(t, "hash_type", hashType.Validators, value); got != wantErr {
			t.Errorf("hash_type %q: rejected=%v, want rejected=%v", value, got, wantErr)
		}
	}

	action := resourceStringAttribute(t, r, "action")
	for value, wantErr := range map[string]bool{"allow": false, "detect": false, "block": true} {
		if got := runStringValidators(t, "action", action.Validators, value); got != wantErr {
			t.Errorf("action %q: rejected=%v, want rejected=%v", value, got, wantErr)
		}
	}
}
