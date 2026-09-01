package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// logGoneFromState records that a Read found its object missing upstream and is
// dropping it from state, which otherwise shows up only as a silent recreate in
// the next plan. The framework already stamps tf_rpc and tf_resource_type onto
// ctx, so the resource type does not need repeating at the call site.
//
// This is the one thing the centralized request logging in internal/client
// cannot say: whether a 404 was fatal or expected drift handling.
func logGoneFromState(ctx context.Context, id string) {
	// "Upwind API" is load-bearing: README's troubleshooting flow finds provider
	// lines with `grep "Upwind API"`, and this is the one line that explains an
	// otherwise-silent recreate. It has to land in the same grep as the request
	// logging in internal/client.
	tflog.Debug(ctx, "Object no longer exists in the Upwind API; removing it from state", map[string]any{
		"upwind_id": id,
	})
}
