package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const ruleDefinitionsPath = "/threats/rule-definitions"

// RuleDefinition mirrors the API rule definition object: the Rego expression that
// detects a threat, independent of any policy it is attached to.
type RuleDefinition struct {
	RuleDefinitionID string             `json:"rule_definition_id,omitempty"`
	Name             string             `json:"name,omitempty"`
	Engine           string             `json:"engine,omitempty"`
	ThreatCategory   string             `json:"threat_category,omitempty"`
	RuleExpression   string             `json:"rule_expression,omitempty"`
	Metadata         RuleDefinitionMeta `json:"metadata"`
	CreateTime       string             `json:"create_time,omitempty"`
	UpdateTime       string             `json:"update_time,omitempty"`
	CreatorID        string             `json:"creator_id,omitempty"`
	LastModifierID   string             `json:"last_modifier_id,omitempty"`
}

// RuleDefinitionMeta is the display and MITRE ATT&CK metadata. Only the two
// detection_* fields are required by the API; the mitre_* fields are optional.
type RuleDefinitionMeta struct {
	DetectionTitle       string `json:"detection_title"`
	DetectionDescription string `json:"detection_description"`
	MitreTacticCode      string `json:"mitre_tactic_code,omitempty"`
	MitreTacticName      string `json:"mitre_tactic_name,omitempty"`
	MitreTechniqueCode   string `json:"mitre_technique_code,omitempty"`
	MitreTechniqueName   string `json:"mitre_technique_name,omitempty"`
}

// CreateRuleDefinitionRequest is one element of the bulk create body.
type CreateRuleDefinitionRequest struct {
	Name           string             `json:"name"`
	Engine         string             `json:"engine"`
	ThreatCategory string             `json:"threat_category"`
	RuleExpression string             `json:"rule_expression"`
	Metadata       RuleDefinitionMeta `json:"metadata"`
}

// UpdateRuleDefinitionRequest is one element of the bulk edit body. The edit
// endpoint accepts no engine or threat_category, so those are immutable.
type UpdateRuleDefinitionRequest struct {
	ID             string              `json:"id"`
	Name           *string             `json:"name,omitempty"`
	RuleExpression *string             `json:"rule_expression,omitempty"`
	Metadata       *RuleDefinitionMeta `json:"metadata,omitempty"`
}

// Bulk request envelopes. As with threat policies, the API exposes no singular
// create/update/delete, and the bulk endpoints are all-or-nothing.
type (
	bulkCreateRuleDefinitionsRequest struct {
		RuleDefinitions []CreateRuleDefinitionRequest `json:"rule_definitions"`
	}
	bulkEditRuleDefinitionsRequest struct {
		RuleDefinitions []UpdateRuleDefinitionRequest `json:"rule_definitions"`
	}
	bulkDeleteRuleDefinitionsRequest struct {
		RuleDefinitionIDs []string `json:"rule_definition_ids"`
	}
)

type ruleDefinitionEnvelope struct {
	Items []RuleDefinition `json:"items"`
}

// GetRuleDefinition fetches a single rule definition by id.
func (c *Client) GetRuleDefinition(ctx context.Context, id string) (*RuleDefinition, error) {
	body, err := c.doRequest(ctx, http.MethodGet, ruleDefinitionsPath+"/"+id, nil)
	if err != nil {
		return nil, err
	}
	return decodeRuleDefinition(body)
}

// CreateRuleDefinition creates one rule definition via the bulk endpoint.
func (c *Client) CreateRuleDefinition(ctx context.Context, req CreateRuleDefinitionRequest) (*RuleDefinition, error) {
	body, err := c.doRequest(ctx, http.MethodPost, ruleDefinitionsPath+"/bulk",
		bulkCreateRuleDefinitionsRequest{RuleDefinitions: []CreateRuleDefinitionRequest{req}})
	if err != nil {
		return nil, err
	}
	return decodeRuleDefinition(body)
}

// UpdateRuleDefinition applies a partial update to one rule definition.
func (c *Client) UpdateRuleDefinition(ctx context.Context, req UpdateRuleDefinitionRequest) (*RuleDefinition, error) {
	body, err := c.doRequest(ctx, http.MethodPatch, ruleDefinitionsPath+"/bulk",
		bulkEditRuleDefinitionsRequest{RuleDefinitions: []UpdateRuleDefinitionRequest{req}})
	if err != nil {
		return nil, err
	}
	return decodeRuleDefinition(body)
}

// DeleteRuleDefinition removes one rule definition by id.
func (c *Client) DeleteRuleDefinition(ctx context.Context, id string) error {
	_, err := c.doRequest(ctx, http.MethodDelete, ruleDefinitionsPath+"/bulk",
		bulkDeleteRuleDefinitionsRequest{RuleDefinitionIDs: []string{id}})
	return err
}

func decodeRuleDefinition(body []byte) (*RuleDefinition, error) {
	var env ruleDefinitionEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding rule definition response: %w", err)
	}
	if len(env.Items) == 0 {
		return nil, fmt.Errorf("rule definition response contained no items")
	}
	return &env.Items[0], nil
}
