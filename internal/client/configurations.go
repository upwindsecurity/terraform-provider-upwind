package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

const (
	configurationFindingsPath = "/configurations/findings"
	assetExamplesPath         = "/configurations/asset-examples"
)

// ErrFiltersRequired marks a findings search with no conditions.
//
// Unlike /threats/stories there is no plain GET collection endpoint for findings:
// POST /configurations/findings/search is the only way to list them, and it
// rejects an empty conditions list with a 400. Callers therefore cannot express
// "every finding", so this fails locally rather than spending a round trip to
// learn the same thing.
var ErrFiltersRequired = errors.New("upwind: at least one filter is required to search configuration findings")

// ConfigurationFinding mirrors an API configuration finding: the outcome of
// evaluating one compliance rule against one cloud resource. Findings are
// produced by the platform - there is no create endpoint - so the provider
// exposes them read-only.
//
// Like threat stories, the singular and collection endpoints return different
// shapes: GET /{id} nests a richer framework object (compliance_status,
// last_scan_time, rollout_state, type) than /search does. Only the fields common
// to both are modelled, so one type serves both calls and no attribute is
// populated on one path and silently null on the other.
type ConfigurationFinding struct {
	ID             string   `json:"id,omitempty"`
	Title          string   `json:"title,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Status         string   `json:"status,omitempty"`
	EvaluationTime string   `json:"evaluation_time,omitempty"`
	FirstSeenTime  string   `json:"first_seen_time,omitempty"`
	RiskCategories []string `json:"risk_categories,omitempty"`

	Framework ConfigurationFindingFramework `json:"framework"`
	Resource  ConfigurationFindingResource  `json:"resource"`
	Rule      ConfigurationFindingRule      `json:"rule"`
}

// ConfigurationFindingFramework is the compliance framework the finding's rule
// belongs to. Note `status` here is the string "enabled"/"disabled", whereas the
// frameworks create/update endpoints use an `is_enabled` boolean for the same
// concept - the API has three representations of a framework and this is the one
// findings return.
type ConfigurationFindingFramework struct {
	ID                string `json:"id,omitempty"`
	Title             string `json:"title,omitempty"`
	Description       string `json:"description,omitempty"`
	CloudProviderName string `json:"cloud_provider_name,omitempty"`
	Status            string `json:"status,omitempty"`
	Revision          string `json:"revision,omitempty"`
	Version           string `json:"version,omitempty"`
}

// ConfigurationFindingRule is the rule that produced the finding, including the
// remediation text shown to a practitioner.
type ConfigurationFindingRule struct {
	ID          string `json:"id,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ConfigurationFindingResource is the cloud resource the rule was evaluated
// against.
//
// cloud_account_tags is deliberately not modelled. It is a list of
// key/value objects nested three deep inside the findings list, and tags are
// already reachable as a filter (`cloud_account_tags`, "key=value" form). Add it
// if someone needs to read tags back rather than filter on them.
type ConfigurationFindingResource struct {
	ID                string `json:"id,omitempty"`
	Name              string `json:"name,omitempty"`
	Type              string `json:"type,omitempty"`
	ARN               string `json:"arn,omitempty"`
	CloudAccountID    string `json:"cloud_account_id,omitempty"`
	CloudAccountName  string `json:"cloud_account_name,omitempty"`
	CloudProviderName string `json:"cloud_provider_name,omitempty"`
	ClusterID         string `json:"cluster_id,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Region            string `json:"region,omitempty"`
	SyncTime          string `json:"sync_time,omitempty"`
	UpwindAssetID     string `json:"upwind_asset_id,omitempty"`
}

// ConfigurationFindingFilter is one search condition. Supported fields are
// status, severity, evaluation_time, first_seen_time, upwind_asset_id,
// resource_name, rule_title, rule_id, framework_id, framework_title, and
// cloud_account_tags; supported operators are eq, in, gt, and lt.
//
// A condition naming a field the data does not populate matches nothing and
// raises no error, so a typo'd value reads as "no findings" rather than as a
// mistake. cloud_account_tags is the sharp edge: its values must be "key=value"
// strings, and a bare key silently matches zero findings.
type ConfigurationFindingFilter struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Value    []string `json:"value"`
}

type configurationFindingEnvelope struct {
	Items    []ConfigurationFinding `json:"items"`
	Metadata PaginationMetadata     `json:"metadata"`
}

// GetConfigurationFinding fetches a single finding by id.
func (c *Client) GetConfigurationFinding(ctx context.Context, id string) (*ConfigurationFinding, error) {
	body, err := c.doRequest(ctx, http.MethodGet, configurationFindingsPath+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	var env configurationFindingEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding configuration finding response: %w", err)
	}
	if len(env.Items) == 0 {
		return nil, fmt.Errorf("configuration finding %q: %w", id, ErrNotFound)
	}
	return &env.Items[0], nil
}

// SearchConfigurationFindings returns the findings matching the given filters,
// paging until the results run out or maxResults is reached. At least one filter
// is required - see ErrFiltersRequired.
//
// pageSize tunes the fetch; maxResults caps what comes back, and with it the
// size of the Terraform state, since every finding returned is written there and
// a finding is a large object. Zero means unlimited for both. The second return
// value reports truncation: a caller that counts results has no other way to tell.
func (c *Client) SearchConfigurationFindings(ctx context.Context, filters []ConfigurationFindingFilter, pageSize, maxResults int) ([]ConfigurationFinding, bool, error) {
	if len(filters) == 0 {
		return nil, false, ErrFiltersRequired
	}

	conditions := make([]searchCondition, 0, len(filters))
	for _, f := range filters {
		conditions = append(conditions, searchCondition(f))
	}

	// Never ask for more than the cap; unset, it makes a small cap one round trip.
	if maxResults > 0 && (pageSize == 0 || pageSize > maxResults) {
		pageSize = maxResults
	}

	var all []ConfigurationFinding
	cursor := ""

	for {
		q := url.Values{}
		if pageSize > 0 {
			q.Set("limit", strconv.Itoa(pageSize))
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}

		path := configurationFindingsPath + "/search"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}

		body, err := c.doRequest(ctx, http.MethodPost, path, searchRequest{Conditions: conditions})
		if err != nil {
			return nil, false, err
		}

		var env configurationFindingEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			return nil, false, fmt.Errorf("decoding configuration finding search response: %w", err)
		}
		all = append(all, env.Items...)

		// Before the cursor, so the cap stops the paging rather than trimming what
		// was already paid for. Exactly maxResults with no next page is complete.
		if maxResults > 0 && len(all) >= maxResults {
			return all[:maxResults], len(all) > maxResults || env.Metadata.NextCursor != "", nil
		}

		// An absent next_cursor means this was the last page. Guard against a
		// server that echoes the same cursor back, which would loop forever.
		if env.Metadata.NextCursor == "" || env.Metadata.NextCursor == cursor {
			return all, false, nil
		}
		cursor = env.Metadata.NextCursor
	}
}

// GetAssetExample returns example assets of the given kind as raw JSON.
//
// The payload is deliberately not modelled: the API types `items` as an untyped
// array, and the shape is per-asset-kind - an aws_s3_bucket and a kubernetes_pod
// share almost no fields - so there is nothing stable to declare. The JSON is
// handed to the practitioner, who decodes the parts they need. Its purpose is
// authoring Rego for a configuration custom rule, which needs the shape of the
// input document rather than any particular field.
//
// cloudAccountID is optional; when set, the example is drawn from that account.
func (c *Client) GetAssetExample(ctx context.Context, assetKind, cloudAccountID string) (json.RawMessage, error) {
	path := assetExamplesPath + "/" + url.PathEscape(assetKind)
	if cloudAccountID != "" {
		path += "?" + url.Values{"cloud-account-id": {cloudAccountID}}.Encode()
	}

	body, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	// Held as raw elements so each example's own keys and ordering survive
	// untouched; only the array length is inspected.
	var env struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding asset example response: %w", err)
	}
	if len(env.Items) == 0 {
		return nil, fmt.Errorf("asset example for kind %q: %w", assetKind, ErrNotFound)
	}

	out, err := json.Marshal(env.Items)
	if err != nil {
		return nil, fmt.Errorf("re-encoding asset example response: %w", err)
	}
	return out, nil
}
