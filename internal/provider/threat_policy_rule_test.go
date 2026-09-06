package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestSeverityRemovalRequiresReplace pins the one direction that must force a
// replacement. The API cannot clear a severity override in place, so if this
// condition ever loosens, removing `severity` from a config silently leaves the
// override live on the server with state recording null.
func TestSeverityRemovalRequiresReplace(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state, cfg  types.String
		wantReplace bool
	}{
		{"removed", types.StringValue("critical"), types.StringNull(), true},
		{"changed", types.StringValue("critical"), types.StringValue("low"), false},
		{"added", types.StringNull(), types.StringValue("high"), false},
		{"never set", types.StringNull(), types.StringNull(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &stringplanmodifier.RequiresReplaceIfFuncResponse{}
			severityRemovalRequiresReplace(context.Background(), planmodifier.StringRequest{
				StateValue:  tc.state,
				ConfigValue: tc.cfg,
			}, resp)
			if resp.RequiresReplace != tc.wantReplace {
				t.Errorf("RequiresReplace = %v, want %v", resp.RequiresReplace, tc.wantReplace)
			}
		})
	}
}
