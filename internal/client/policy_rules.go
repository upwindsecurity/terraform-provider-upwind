package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// policyRulesPath builds the rules sub-path for one policy, e.g.
// /threats/policies/policy_1/rules
func policyRulesPath(policyID string) string {
	return threatPoliciesPath + "/" + policyID + "/rules"
}

// PolicyRule mirrors the API policy rule object: one rule definition attached to
// one policy, optionally overriding the policy's severity and scope.
//
// Several read fields are EFFECTIVE values rather than what was written:
// Severity falls back to the policy's severity when the rule sets none, and
// Scope falls back to the policy's scope. ScopeType names which source won, and
// the provider uses it to avoid recording an inherited scope as a rule-owned one.
type PolicyRule struct {
	PolicyRuleID       string         `json:"policy_rule_id,omitempty"`
	PolicyID           string         `json:"policy_id,omitempty"`
	RuleDefinitionID   string         `json:"rule_definition_id,omitempty"`
	RuleDefinitionName string         `json:"rule_definition_name,omitempty"`
	ThreatCategory     string         `json:"threat_category,omitempty"`
	Severity           string         `json:"severity,omitempty"`
	IsEnabled          bool           `json:"is_enabled"`
	IsSuspended        bool           `json:"is_suspended"`
	Scope              *ResourceScope `json:"scope,omitempty"`
	ScopeType          string         `json:"scope_type,omitempty"`
	CreateTime         string         `json:"create_time,omitempty"`
	UpdateTime         string         `json:"update_time,omitempty"`
	CreatorID          string         `json:"creator_id,omitempty"`
	LastModifierID     string         `json:"last_modifier_id,omitempty"`
}

// CreatePolicyRuleRequest is one element of the bulk create body. Only
// rule_definition_id is required; severity and scope default to the policy's.
type CreatePolicyRuleRequest struct {
	RuleDefinitionID string         `json:"rule_definition_id"`
	IsEnabled        *bool          `json:"is_enabled,omitempty"`
	Severity         *string        `json:"severity,omitempty"`
	Scope            *ResourceScope `json:"scope,omitempty"`
}

// UpdatePolicyRuleRequest is one element of the bulk edit body. The edit endpoint
// accepts no rule_definition_id, so re-pointing a rule is a replacement.
type UpdatePolicyRuleRequest struct {
	ID        string         `json:"id"`
	IsEnabled *bool          `json:"is_enabled,omitempty"`
	Severity  *string        `json:"severity,omitempty"`
	Scope     *ResourceScope `json:"scope,omitempty"`
}

type (
	bulkCreatePolicyRulesRequest struct {
		PolicyRules []CreatePolicyRuleRequest `json:"policy_rules"`
	}
	bulkEditPolicyRulesRequest struct {
		PolicyRules []UpdatePolicyRuleRequest `json:"policy_rules"`
	}
	bulkDeletePolicyRulesRequest struct {
		PolicyRuleIDs []string `json:"policy_rule_ids"`
	}
)

type policyRuleEnvelope struct {
	Items []PolicyRule `json:"items"`
}

// GetPolicyRule fetches a single policy rule by policy id and rule id.
func (c *Client) GetPolicyRule(ctx context.Context, policyID, ruleID string) (*PolicyRule, error) {
	body, err := c.doRequest(ctx, http.MethodGet, policyRulesPath(policyID)+"/"+ruleID, nil)
	if err != nil {
		return nil, err
	}
	return decodePolicyRule(body)
}

// CreatePolicyRule attaches one rule definition to a policy via the bulk endpoint.
func (c *Client) CreatePolicyRule(ctx context.Context, policyID string, req CreatePolicyRuleRequest) (*PolicyRule, error) {
	body, err := c.doRequest(ctx, http.MethodPost, policyRulesPath(policyID)+"/bulk",
		bulkCreatePolicyRulesRequest{PolicyRules: []CreatePolicyRuleRequest{req}})
	if err != nil {
		return nil, err
	}
	return decodePolicyRule(body)
}

// UpdatePolicyRule applies a partial update to one policy rule.
func (c *Client) UpdatePolicyRule(ctx context.Context, policyID string, req UpdatePolicyRuleRequest) (*PolicyRule, error) {
	body, err := c.doRequest(ctx, http.MethodPatch, policyRulesPath(policyID)+"/bulk",
		bulkEditPolicyRulesRequest{PolicyRules: []UpdatePolicyRuleRequest{req}})
	if err != nil {
		return nil, err
	}
	return decodePolicyRule(body)
}

// DeletePolicyRule detaches one rule from a policy. There is no singular DELETE,
// so this goes through the bulk endpoint with a one-element array.
func (c *Client) DeletePolicyRule(ctx context.Context, policyID, ruleID string) error {
	_, err := c.doRequest(ctx, http.MethodDelete, policyRulesPath(policyID)+"/bulk",
		bulkDeletePolicyRulesRequest{PolicyRuleIDs: []string{ruleID}})
	return err
}

func decodePolicyRule(body []byte) (*PolicyRule, error) {
	var env policyRuleEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding policy rule response: %w", err)
	}
	if len(env.Items) == 0 {
		return nil, fmt.Errorf("policy rule response contained no items")
	}
	return &env.Items[0], nil
}
