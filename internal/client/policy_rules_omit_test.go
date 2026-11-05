package client

import (
	"encoding/json"
	"strings"
	"testing"
)

// Inherit vs owned is carried entirely by whether is_enabled appears in the body.
func TestCreatePolicyRuleRequestOmitsIsEnabledWhenUnset(t *testing.T) {
	body, err := json.Marshal(CreatePolicyRuleRequest{RuleDefinitionID: "rd_1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "is_enabled") {
		t.Errorf("omitted is_enabled must not reach the wire, got %s", body)
	}
}

func TestCreatePolicyRuleRequestSendsAnExplicitFalse(t *testing.T) {
	// The opposite error: dropping a deliberate `is_enabled = false`.
	f := false
	body, err := json.Marshal(CreatePolicyRuleRequest{RuleDefinitionID: "rd_1", IsEnabled: &f})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"is_enabled":false`) {
		t.Errorf("explicit false must reach the wire, got %s", body)
	}
}

func TestUpdatePolicyRuleRequestOmitsIsEnabledWhenUnset(t *testing.T) {
	body, err := json.Marshal(UpdatePolicyRuleRequest{ID: "pr_1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "is_enabled") {
		t.Errorf("omitted is_enabled must not reach the wire, got %s", body)
	}
}
