package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- rule definitions ---

func TestCreateRuleDefinition_WrapsInBulkEnvelope(t *testing.T) {
	var body bulkCreateRuleDefinitionsRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/v2/organizations/org_test/threats/rule-definitions/bulk"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		_ = json.NewEncoder(w).Encode(ruleDefinitionEnvelope{Items: []RuleDefinition{{
			RuleDefinitionID: "rd_1", Name: "Unauthorized API Call", Engine: "rego",
			ThreatCategory: "cloud_trail_logs", RuleExpression: "package policy.custom.cloud_trail_logs",
		}}})
	}))
	defer srv.Close()

	rd, err := newTestClient(srv).CreateRuleDefinition(context.Background(), CreateRuleDefinitionRequest{
		Name: "Unauthorized API Call", Engine: "rego", ThreatCategory: "cloud_trail_logs",
		RuleExpression: "package policy.custom.cloud_trail_logs",
		Metadata:       RuleDefinitionMeta{DetectionTitle: "T", DetectionDescription: "D"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.RuleDefinitions) != 1 {
		t.Fatalf("expected one rule definition in the bulk body, got %d", len(body.RuleDefinitions))
	}
	if rd.RuleDefinitionID != "rd_1" {
		t.Errorf("id: got %q, want %q", rd.RuleDefinitionID, "rd_1")
	}
}

func TestDeleteRuleDefinition_UsesIDsArray(t *testing.T) {
	var body bulkDeleteRuleDefinitionsRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodDelete; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeleteRuleDefinition(context.Background(), "rd_1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.RuleDefinitionIDs) != 1 || body.RuleDefinitionIDs[0] != "rd_1" {
		t.Errorf("rule_definition_ids: got %v, want [rd_1]", body.RuleDefinitionIDs)
	}
}

// --- policy rules ---

// Policy rules are nested under their policy, so every path must carry both ids.
func TestGetPolicyRule_NestedPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/v2/organizations/org_test/threats/policies/policy_1/rules/pr_2"
		if got := r.URL.Path; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		_ = json.NewEncoder(w).Encode(policyRuleEnvelope{Items: []PolicyRule{{
			PolicyRuleID: "pr_2", PolicyID: "policy_1", RuleDefinitionID: "rd_1",
			Severity: "high", ScopeType: "policy_scope", IsEnabled: true,
		}}})
	}))
	defer srv.Close()

	pr, err := newTestClient(srv).GetPolicyRule(context.Background(), "policy_1", "pr_2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.PolicyRuleID != "pr_2" || pr.PolicyID != "policy_1" {
		t.Errorf("unexpected ids: %+v", pr)
	}
}

func TestDeletePolicyRule_UsesNestedBulkPath(t *testing.T) {
	var body bulkDeletePolicyRulesRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/v2/organizations/org_test/threats/policies/policy_1/rules/bulk"
		if got := r.URL.Path; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeletePolicyRule(context.Background(), "policy_1", "pr_2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.PolicyRuleIDs) != 1 || body.PolicyRuleIDs[0] != "pr_2" {
		t.Errorf("policy_rule_ids: got %v, want [pr_2]", body.PolicyRuleIDs)
	}
}

// --- malware indicators ---

// Read is search-backed: the request must filter on hash, since there is no
// GET-by-id endpoint.
func TestGetMalwareIndicator_SearchesByHash(t *testing.T) {
	var body searchRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/v2/organizations/org_test/threats/management/indicators/malware/search"
		if got := r.URL.Path; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		if got, wantM := r.Method, http.MethodPost; got != wantM {
			t.Errorf("method: got %s, want %s", got, wantM)
		}
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		_ = json.NewEncoder(w).Encode(malwareIndicatorEnvelope{Items: []MalwareIndicator{{
			Hash: "abc123", HashType: "sha1", Action: "allow", Reason: "known good",
		}}})
	}))
	defer srv.Close()

	mi, err := newTestClient(srv).GetMalwareIndicator(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.Conditions) != 1 || body.Conditions[0].Field != "hash" || body.Conditions[0].Value[0] != "abc123" {
		t.Errorf("search conditions: got %+v", body.Conditions)
	}
	if mi.Action != "allow" {
		t.Errorf("action: got %q, want %q", mi.Action, "allow")
	}
}

// A hash with no override comes back as 200 with an empty items array, never a
// 404. It must still satisfy IsNotFound, or Read cannot drop the resource from
// state and every refresh errors instead.
func TestGetMalwareIndicator_EmptySearchIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(malwareIndicatorEnvelope{Items: []MalwareIndicator{}})
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetMalwareIndicator(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound: got false, want true (err: %v)", err)
	}
}

// Deletion is keyed by (hash, hash_type), not by a generated id.
func TestDeleteMalwareIndicator_UsesHashPair(t *testing.T) {
	var body bulkDeleteMalwareIndicatorsRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeleteMalwareIndicator(context.Background(), "abc123", "sha1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.Items) != 1 || body.Items[0].Hash != "abc123" || body.Items[0].HashType != "sha1" {
		t.Errorf("delete items: got %+v", body.Items)
	}
}
