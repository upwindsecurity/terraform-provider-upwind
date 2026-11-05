package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// shortConsistencyBudget keeps the exhaustion cases in milliseconds, not 15s.
func shortConsistencyBudget(t *testing.T) {
	t.Helper()
	budget, first, max := consistencyBudget, consistencyFirstWait, consistencyMaxWait
	consistencyBudget, consistencyFirstWait, consistencyMaxWait = 150*time.Millisecond, time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() {
		consistencyBudget, consistencyFirstWait, consistencyMaxWait = budget, first, max
	})
}

// notFoundThenOK answers 404 for the first `n` requests, then serves `body`.
func notFoundThenOK(n int32, body any, calls *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(calls, 1) <= n {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Policy not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}
}

func TestCreatePolicyRuleRetriesOn404(t *testing.T) {
	shortConsistencyBudget(t)
	var calls int32
	srv := httptest.NewServer(notFoundThenOK(2,
		policyRuleEnvelope{Items: []PolicyRule{{PolicyRuleID: "pr_1", PolicyID: "policy_1"}}}, &calls))
	defer srv.Close()

	pr, err := newTestClient(srv).CreatePolicyRule(context.Background(), "policy_1",
		CreatePolicyRuleRequest{RuleDefinitionID: "rd_1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.PolicyRuleID != "pr_1" {
		t.Errorf("id: got %q, want %q", pr.PolicyRuleID, "pr_1")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("attempts: got %d, want 3 (two 404s then success)", got)
	}
}

func TestCreatePolicyRuleReturnsTheOriginal404WhenTheBudgetIsSpent(t *testing.T) {
	// A wrong policy_id must fail as a 404, not a timeout.
	shortConsistencyBudget(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Policy not found"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).CreatePolicyRule(context.Background(), "policy_missing",
		CreatePolicyRuleRequest{RuleDefinitionID: "rd_1"})
	if !IsNotFound(err) {
		t.Fatalf("want a not-found error, got %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("want the original *APIError 404, got %#v", err)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("expected more than one attempt, got %d", calls)
	}
}

func TestCreatePolicyRuleDoesNotRetryOtherErrors(t *testing.T) {
	// A 5xx may have stored the rule it failed to acknowledge; replaying duplicates.
	shortConsistencyBudget(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	_, _ = newTestClient(srv).CreatePolicyRule(context.Background(), "policy_1",
		CreatePolicyRuleRequest{RuleDefinitionID: "rd_1"})
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("a 409 must not be retried by this helper: got %d attempts, want 1", got)
	}
}

func TestGetPolicyRuleDoesNotRetryA404(t *testing.T) {
	// REGRESSION GUARD: Read's 404 is what drops a deleted rule out of state.
	shortConsistencyBudget(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetPolicyRule(context.Background(), "policy_1", "pr_1")
	if !IsNotFound(err) {
		t.Fatalf("want not-found, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("read path must 404 immediately: got %d attempts, want 1", got)
	}
}

func TestGetThreatPolicyDoesNotRetryA404(t *testing.T) {
	// Same guard for the policy read path.
	shortConsistencyBudget(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetThreatPolicy(context.Background(), "policy_1")
	if !IsNotFound(err) {
		t.Fatalf("want not-found, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("read path must 404 immediately: got %d attempts, want 1", got)
	}
}

func TestGetThreatPolicyAfterWriteWaitsForVisibility(t *testing.T) {
	shortConsistencyBudget(t)
	var calls int32
	srv := httptest.NewServer(notFoundThenOK(1,
		threatPolicyEnvelope{Items: []ThreatPolicy{{PolicyID: "policy_1", Name: "p"}}}, &calls))
	defer srv.Close()

	p, err := newTestClient(srv).GetThreatPolicyAfterWrite(context.Background(), "policy_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PolicyID != "policy_1" {
		t.Errorf("id: got %q, want %q", p.PolicyID, "policy_1")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("attempts: got %d, want 2", got)
	}
}

func TestRetryWhileNotFoundStopsOnContextCancellation(t *testing.T) {
	// An interrupted apply cancels ctx; the wait must abandon, not hold the budget.
	shortConsistencyBudget(t)
	consistencyBudget = 10 * time.Second // long enough that only cancellation ends it
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	start := time.Now()
	_, err := newTestClient(srv).GetThreatPolicyAfterWrite(ctx, "policy_1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v; should abandon promptly on cancellation", elapsed)
	}
}

func TestGetPolicyRuleAfterWriteWaitsForVisibility(t *testing.T) {
	// Unguarded, a 404 here made Create error without setting state, leaving a rule
	// the next apply would duplicate.
	shortConsistencyBudget(t)
	var calls int32
	srv := httptest.NewServer(notFoundThenOK(1,
		policyRuleEnvelope{Items: []PolicyRule{{PolicyRuleID: "pr_1", PolicyID: "policy_1"}}}, &calls))
	defer srv.Close()

	pr, err := newTestClient(srv).GetPolicyRuleAfterWrite(context.Background(), "policy_1", "pr_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.PolicyRuleID != "pr_1" {
		t.Errorf("id: got %q, want %q", pr.PolicyRuleID, "pr_1")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("attempts: got %d, want 2", got)
	}
}
