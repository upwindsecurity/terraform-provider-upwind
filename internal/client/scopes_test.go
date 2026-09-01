package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestClient returns a Client pointed at the given test server, bypassing the
// OAuth token exchange so request/decode logic can be tested in isolation.
func newTestClient(srv *httptest.Server) *Client {
	return newClient(srv.Client(), srv.URL, "org_test", UserAgent("test"))
}

func TestGetScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodGet; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		if got, want := r.URL.Path, "/v2/organizations/org_test/access-management/scopes/scope_1"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		_ = json.NewEncoder(w).Encode(scopeEnvelope{Items: []Scope{{
			ID:          "scope_1",
			Name:        "AWS Production",
			Description: "prod aws",
			ResourceFilters: []ResourceFilter{
				{Attribute: "cloud_provider", Operator: "eq", Values: []string{"aws"}},
			},
			CreateTime: "2026-01-01T00:00:00Z",
		}}})
	}))
	defer srv.Close()

	scope, err := newTestClient(srv).GetScope(context.Background(), "scope_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope.Name != "AWS Production" {
		t.Errorf("name: got %q, want %q", scope.Name, "AWS Production")
	}
	if len(scope.ResourceFilters) != 1 || scope.ResourceFilters[0].Values[0] != "aws" {
		t.Errorf("unexpected filters: %+v", scope.ResourceFilters)
	}
}

func TestGetScope_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetScope(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("expected IsNotFound to be true for err: %v", err)
	}
}

func TestCreateScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		var got CreateScopeRequest
		bodyBytes, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(bodyBytes, &got); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if got.Name != "New Scope" {
			t.Errorf("request name: got %q, want %q", got.Name, "New Scope")
		}
		_ = json.NewEncoder(w).Encode(scopeEnvelope{Items: []Scope{{ID: "scope_new", Name: got.Name}}})
	}))
	defer srv.Close()

	scope, err := newTestClient(srv).CreateScope(context.Background(), CreateScopeRequest{
		Name:            "New Scope",
		ResourceFilters: []ResourceFilter{{Attribute: "a", Operator: "eq", Values: []string{"b"}}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope.ID != "scope_new" {
		t.Errorf("id: got %q, want %q", scope.ID, "scope_new")
	}
}
