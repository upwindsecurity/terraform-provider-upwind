package provider

import (
	"maps"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Shared schema for the data sources that read a collection
// (upwind_threat_stories, upwind_configuration_findings).

// collectionStateWarning is appended to a collection data source's description.
// Kept in one place because the warning is only useful on every collection.
const collectionStateWarning = "\n\n~> **Every result is written to the Terraform state file and printed in the " +
	"plan output.** State is read and rewritten on every operation, so a large result set slows " +
	"down every subsequent plan and apply, not only this read. Keep `filters` narrow and set " +
	"`max_results`; an unbounded read on a large organization is the case this warning exists for."

// paginationAttributes returns the page_size / max_results / truncated trio.
// noun is what is being counted, e.g. "findings", so the generated docs read
// naturally. The two knobs are separate because the API's own `limit` means page
// size, which a practitioner reads as a cap on results - it never was one.
func paginationAttributes(noun string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"page_size": schema.Int64Attribute{
			Optional: true,
			MarkdownDescription: "How many " + noun + " to request per API call while paging. A tuning knob only: " +
				"it does not cap how many are returned - use `max_results` for that. Defaults to the API's own page size. " +
				"When `max_results` is set and this is not, the page size follows `max_results`, so a small cap costs one request.",
			Validators: []validator.Int64{int64validator.AtLeast(1)},
		},
		"max_results": schema.Int64Attribute{
			Optional: true,
			MarkdownDescription: "Maximum number of " + noun + " to return. Paging stops once this many have been " +
				"collected, so it bounds both the number of API calls and the size of the Terraform state. " +
				"Omit for no cap, which on a large organization can mean everything - see the note above. " +
				"Check `truncated` to find out whether the cap was hit.",
			Validators: []validator.Int64{int64validator.AtLeast(1)},
		},
		"truncated": schema.BoolAttribute{
			Computed: true,
			MarkdownDescription: "Whether more " + noun + " matched than were returned, because `max_results` was reached. " +
				"Always `false` when `max_results` is unset. Worth asserting on when the count itself drives a decision " +
				"(a `check` block that fails a deploy on open findings, say): a truncated list makes a count wrong " +
				"in the safe-looking direction.",
		},
	}
}

// mergeAttributes lets a schema stay one literal. paginationAttributes returns a
// fresh map each call, so mutating dst is safe.
func mergeAttributes(dst, src map[string]schema.Attribute) map[string]schema.Attribute {
	maps.Copy(dst, src)
	return dst
}
