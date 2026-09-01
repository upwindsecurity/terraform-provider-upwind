package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const threatPoliciesPath = "/threats/policies"

// ThreatPolicy mirrors the API threat policy object returned by reads and by the
// bulk write endpoints.
//
// Note the read/write asymmetry: writes send `default_severity`, reads return the
// same value as `severity`. The provider maps both onto one `severity` attribute.
//
// `default_values` (the pre-override state of a managed policy) is
// deliberately not modelled. It is server-owned, appears and disappears based on
// whether a tenant override is active, and nothing in a plan depends on it -
// decoding it would only invite false drift. Add it as a Computed-only attribute
// if a data source ever needs to surface override status.
type ThreatPolicy struct {
	PolicyID       string               `json:"policy_id,omitempty"`
	Name           string               `json:"name,omitempty"`
	Severity       string               `json:"severity,omitempty"`
	SourceType     string               `json:"source_type,omitempty"`
	IsEnabled      bool                 `json:"is_enabled"`
	Metadata       ThreatPolicyMetadata `json:"metadata"`
	ResourceScope  *ResourceScope       `json:"resource_scope,omitempty"`
	CreateTime     string               `json:"create_time,omitempty"`
	UpdateTime     string               `json:"update_time,omitempty"`
	CreatorID      string               `json:"creator_id,omitempty"`
	LastModifierID string               `json:"last_modifier_id,omitempty"`
}

// ThreatPolicyMetadata is the display metadata shown on a detection raised by
// this policy. Both fields are required by the API on create.
type ThreatPolicyMetadata struct {
	DetectionTitle       string `json:"detection_title"`
	DetectionDescription string `json:"detection_description"`
}

// ResourceScope limits which cloud resources a policy applies to. A nil Condition
// is serialised as `"condition": null`, which the API reads as "no scope".
type ResourceScope struct {
	Condition *ScopeCondition `json:"condition"`
}

// ScopeCondition is one scope-matching rule. The API discriminates on `type`, but
// all five leaf condition types share this exact shape, so one struct covers them:
// cloud_account_rule, cloud_account_ou_rule, cloud_account_organization_rule,
// cloud_provider_rule, cluster_id_rule.
//
// The sixth type, `filter`, is a recursive composite ({match, conditions[]})
// and is not supported. Terraform's schema model has no clean recursion, and a
// single leaf condition covers ordinary scoping. If nested boolean scopes are ever
// needed, model `filter` as a separate one-level-deep attribute rather than trying
// to make this struct recursive.
type ScopeCondition struct {
	Type     string   `json:"type"`
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Value    []string `json:"value"`
}

// CreateThreatPolicyRequest is one element of the bulk create body.
type CreateThreatPolicyRequest struct {
	Name            string               `json:"name"`
	DefaultSeverity string               `json:"default_severity"`
	SourceType      string               `json:"source_type"`
	Metadata        ThreatPolicyMetadata `json:"metadata"`
	IsEnabled       *bool                `json:"is_enabled,omitempty"`
	ResourceScope   *ResourceScope       `json:"resource_scope,omitempty"`
}

// UpdateThreatPolicyRequest is one element of the bulk edit body. Only ID is
// required; nil fields are omitted so the API leaves them untouched.
type UpdateThreatPolicyRequest struct {
	ID              string                `json:"id"`
	Name            *string               `json:"name,omitempty"`
	DefaultSeverity *string               `json:"default_severity,omitempty"`
	Metadata        *ThreatPolicyMetadata `json:"metadata,omitempty"`
	IsEnabled       *bool                 `json:"is_enabled,omitempty"`
	ResourceScope   *ResourceScope        `json:"resource_scope,omitempty"`
}

// Bulk request envelopes. The API exposes no singular create/update/delete for
// threat policies, so every write goes through /bulk with a one-element array.
// This is safe for a single resource: the bulk endpoints are all-or-nothing
// ("if any item fails validation, no updates are applied"), so a non-2xx means
// our one policy was not written, with no partial state to reconcile.
type (
	bulkCreateThreatPoliciesRequest struct {
		Policies []CreateThreatPolicyRequest `json:"policies"`
	}
	bulkEditThreatPoliciesRequest struct {
		Policies []UpdateThreatPolicyRequest `json:"policies"`
	}
	bulkDeleteThreatPoliciesRequest struct {
		PolicyIDs []string `json:"policy_ids"`
	}
)

// threatPolicyEnvelope is the {items:[...]} wrapper every v2 response uses,
// including single-object GETs.
type threatPolicyEnvelope struct {
	Items []ThreatPolicy `json:"items"`
}

// GetThreatPolicy fetches a single policy by id. A missing policy returns an
// *APIError for which IsNotFound reports true.
func (c *Client) GetThreatPolicy(ctx context.Context, id string) (*ThreatPolicy, error) {
	body, err := c.doRequest(ctx, http.MethodGet, threatPoliciesPath+"/"+id, nil)
	if err != nil {
		return nil, err
	}
	return decodeThreatPolicy(body)
}

// CreateThreatPolicy creates one policy via the bulk endpoint and returns it with
// server-populated fields.
func (c *Client) CreateThreatPolicy(ctx context.Context, req CreateThreatPolicyRequest) (*ThreatPolicy, error) {
	body, err := c.doRequest(ctx, http.MethodPost, threatPoliciesPath+"/bulk",
		bulkCreateThreatPoliciesRequest{Policies: []CreateThreatPolicyRequest{req}})
	if err != nil {
		return nil, err
	}
	return decodeThreatPolicy(body)
}

// UpdateThreatPolicy applies a partial update to one policy via the bulk endpoint.
func (c *Client) UpdateThreatPolicy(ctx context.Context, req UpdateThreatPolicyRequest) (*ThreatPolicy, error) {
	body, err := c.doRequest(ctx, http.MethodPatch, threatPoliciesPath+"/bulk",
		bulkEditThreatPoliciesRequest{Policies: []UpdateThreatPolicyRequest{req}})
	if err != nil {
		return nil, err
	}
	return decodeThreatPolicy(body)
}

// DeleteThreatPolicy removes one policy by id via the bulk endpoint.
func (c *Client) DeleteThreatPolicy(ctx context.Context, id string) error {
	_, err := c.doRequest(ctx, http.MethodDelete, threatPoliciesPath+"/bulk",
		bulkDeleteThreatPoliciesRequest{PolicyIDs: []string{id}})
	return err
}

// decodeThreatPolicy unwraps the {items:[policy]} envelope and returns the single
// policy. An empty items array means the policy does not exist; the API is
// expected to answer 404 in that case, so treat it as an error rather than
// silently returning a zero value.
func decodeThreatPolicy(body []byte) (*ThreatPolicy, error) {
	var env threatPolicyEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding threat policy response: %w", err)
	}
	if len(env.Items) == 0 {
		return nil, fmt.Errorf("threat policy response contained no items")
	}
	return &env.Items[0], nil
}
