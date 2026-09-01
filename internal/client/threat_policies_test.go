package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetThreatPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodGet; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		if got, want := r.URL.Path, "/v2/organizations/org_test/threats/policies/policy_1"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		_ = json.NewEncoder(w).Encode(threatPolicyEnvelope{Items: []ThreatPolicy{{
			PolicyID:   "policy_1",
			Name:       "Privilege Escalation",
			Severity:   "high",
			SourceType: "cloud_logs",
			IsEnabled:  true,
			Metadata: ThreatPolicyMetadata{
				DetectionTitle:       "Privilege Escalation Attempt",
				DetectionDescription: "Surfaces role changes granting elevated access.",
			},
			ResourceScope: &ResourceScope{Condition: &ScopeCondition{
				Type: "cloud_provider_rule", Field: "cloud_provider",
				Operator: "in", Value: []string{"aws", "gcp"},
			}},
			CreateTime: "2026-01-01T00:00:00Z",
		}}})
	}))
	defer srv.Close()

	p, err := newTestClient(srv).GetThreatPolicy(context.Background(), "policy_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "Privilege Escalation" {
		t.Errorf("name: got %q, want %q", p.Name, "Privilege Escalation")
	}
	// The read side returns `severity`, not `default_severity`.
	if p.Severity != "high" {
		t.Errorf("severity: got %q, want %q", p.Severity, "high")
	}
	if p.ResourceScope == nil || p.ResourceScope.Condition == nil {
		t.Fatalf("expected a resource scope condition, got %+v", p.ResourceScope)
	}
	if got := p.ResourceScope.Condition.Value; len(got) != 2 || got[0] != "aws" {
		t.Errorf("condition values: got %v", got)
	}
}

func TestGetThreatPolicy_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetThreatPolicy(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound: got false, want true (err: %v)", err)
	}
}

// A 200 carrying an empty items array is not a valid single-policy response.
// If the API ever answers a missing policy this way instead of 404, we must fail
// loudly rather than hand back a zero-valued policy that would look like drift.
func TestGetThreatPolicy_EmptyItems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(threatPolicyEnvelope{Items: []ThreatPolicy{}})
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).GetThreatPolicy(context.Background(), "policy_1"); err == nil {
		t.Fatal("expected an error for an empty items array, got nil")
	}
}

// Create must wrap the single policy in the bulk envelope and send the severity
// under its write-side name, default_severity.
func TestCreateThreatPolicy_WrapsInBulkEnvelope(t *testing.T) {
	var body bulkCreateThreatPoliciesRequest
	var raw map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		if got, want := r.URL.Path, "/v2/organizations/org_test/threats/policies/bulk"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		_ = json.Unmarshal(decoded, &raw)

		_ = json.NewEncoder(w).Encode(threatPolicyEnvelope{Items: []ThreatPolicy{{
			PolicyID: "policy_new", Name: "Test", Severity: "critical",
			SourceType: "sensor", IsEnabled: true,
		}}})
	}))
	defer srv.Close()

	enabled := true
	p, err := newTestClient(srv).CreateThreatPolicy(context.Background(), CreateThreatPolicyRequest{
		Name:            "Test",
		DefaultSeverity: "critical",
		SourceType:      "sensor",
		Metadata: ThreatPolicyMetadata{
			DetectionTitle: "T", DetectionDescription: "D",
		},
		IsEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.Policies) != 1 {
		t.Fatalf("expected exactly one policy in the bulk body, got %d", len(body.Policies))
	}
	if body.Policies[0].DefaultSeverity != "critical" {
		t.Errorf("default_severity: got %q, want %q", body.Policies[0].DefaultSeverity, "critical")
	}
	// Guard the wire name explicitly: the struct field is DefaultSeverity but the
	// API rejects the read-side name `severity` on write.
	policies := raw["policies"].([]any)
	if _, ok := policies[0].(map[string]any)["default_severity"]; !ok {
		t.Errorf("request body must use default_severity on write, got keys %v", policies[0])
	}
	if p.PolicyID != "policy_new" {
		t.Errorf("id: got %q, want %q", p.PolicyID, "policy_new")
	}
}

func TestUpdateThreatPolicy_SendsID(t *testing.T) {
	var body bulkEditThreatPoliciesRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPatch; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		if got, want := r.URL.Path, "/v2/organizations/org_test/threats/policies/bulk"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		_ = json.NewEncoder(w).Encode(threatPolicyEnvelope{Items: []ThreatPolicy{{
			PolicyID: "policy_1", Name: "Renamed", Severity: "low",
		}}})
	}))
	defer srv.Close()

	name := "Renamed"
	p, err := newTestClient(srv).UpdateThreatPolicy(context.Background(), UpdateThreatPolicyRequest{
		ID: "policy_1", Name: &name,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.Policies) != 1 || body.Policies[0].ID != "policy_1" {
		t.Errorf("edit body must carry the policy id, got %+v", body.Policies)
	}
	if p.Name != "Renamed" {
		t.Errorf("name: got %q, want %q", p.Name, "Renamed")
	}
}

// Delete goes to the bulk endpoint with a policy_ids array, not to /{id}.
func TestDeleteThreatPolicy_UsesPolicyIDsArray(t *testing.T) {
	var body bulkDeleteThreatPoliciesRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodDelete; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		if got, want := r.URL.Path, "/v2/organizations/org_test/threats/policies/bulk"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		decoded, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(decoded, &body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeleteThreatPolicy(context.Background(), "policy_1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.PolicyIDs) != 1 || body.PolicyIDs[0] != "policy_1" {
		t.Errorf("policy_ids: got %v, want [policy_1]", body.PolicyIDs)
	}
}
