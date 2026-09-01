package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetConfigurationFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodGet; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		if got, want := r.URL.Path, "/v2/organizations/org_test/configurations/findings/cf_1"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		_ = json.NewEncoder(w).Encode(configurationFindingEnvelope{Items: []ConfigurationFinding{{
			ID: "cf_1", Title: "Bucket is public", Severity: "high", Status: "fail",
			RiskCategories: []string{"data_exposure"},
			Framework:      ConfigurationFindingFramework{ID: "fw_1", Title: "CIS AWS", Status: "enabled"},
			Resource:       ConfigurationFindingResource{Name: "my-bucket", Region: "us-west-2", CloudAccountID: "12345"},
			Rule:           ConfigurationFindingRule{ID: "cr_1", Title: "No public buckets", Remediation: "Block public access"},
		}}})
	}))
	defer srv.Close()

	f, err := newTestClient(srv).GetConfigurationFinding(context.Background(), "cf_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The nested objects are the reason this data source exists: a finding without
	// its rule and resource says nothing actionable.
	if f.Rule.Remediation != "Block public access" {
		t.Errorf("rule.remediation: got %q", f.Rule.Remediation)
	}
	if f.Resource.Name != "my-bucket" || f.Framework.Title != "CIS AWS" {
		t.Errorf("nested objects not decoded: %+v", f)
	}
}

// A missing finding must satisfy IsNotFound so the data source reports a clean
// config error rather than a decode failure.
func TestGetConfigurationFinding_EmptyItemsIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(configurationFindingEnvelope{Items: []ConfigurationFinding{}})
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetConfigurationFinding(context.Background(), "missing")
	if !IsNotFound(err) {
		t.Errorf("IsNotFound: got false, want true (err: %v)", err)
	}
}

// The whole point of the Required-filters decision: no filters must fail before
// any request is made, since the API has no unfiltered list endpoint to fall
// back on and would answer 400.
func TestSearchConfigurationFindings_NoFiltersFailsWithoutRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no HTTP request should be made when filters are empty")
	}))
	defer srv.Close()

	_, _, err := newTestClient(srv).SearchConfigurationFindings(context.Background(), nil, 0, 0)
	if !errors.Is(err, ErrFiltersRequired) {
		t.Errorf("got %v, want ErrFiltersRequired", err)
	}
}

// Filters must reach the API as search conditions, and pagination must be
// followed to exhaustion - a data source returning only page one would silently
// under-report.
func TestSearchConfigurationFindings_SendsConditionsAndFollowsPagination(t *testing.T) {
	var calls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got, want := r.Method, http.MethodPost; got != want {
			t.Errorf("method: got %s, want %s", got, want)
		}
		if got, want := r.URL.Path, "/v2/organizations/org_test/configurations/findings/search"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}

		// t.Errorf, not t.Fatalf: this runs on the server goroutine, and t.Fatal*
		// calls runtime.Goexit(), which would abort the handler before it writes a
		// response and surface as a confusing transport EOF at the call site.
		var req searchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request body: %v", err)
			return
		}
		if len(req.Conditions) != 1 || req.Conditions[0].Field != "severity" {
			t.Errorf("conditions not forwarded: %+v", req.Conditions)
		}

		switch r.URL.Query().Get("cursor") {
		case "":
			_ = json.NewEncoder(w).Encode(configurationFindingEnvelope{
				Items:    []ConfigurationFinding{{ID: "cf_1"}, {ID: "cf_2"}},
				Metadata: PaginationMetadata{NextCursor: "page2"},
			})
		case "page2":
			_ = json.NewEncoder(w).Encode(configurationFindingEnvelope{
				Items: []ConfigurationFinding{{ID: "cf_3"}},
			})
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer srv.Close()

	findings, truncated, err := newTestClient(srv).SearchConfigurationFindings(
		context.Background(),
		[]ConfigurationFindingFilter{{Field: "severity", Operator: "eq", Value: []string{"high"}}},
		50, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("got %d findings across pages, want 3", len(findings))
	}
	if truncated {
		t.Error("truncated: got true, want false - no max_results was set")
	}
	if calls != 2 {
		t.Errorf("got %d requests, want 2", calls)
	}
}

// A server that echoes the same cursor back must not loop forever.
func TestSearchConfigurationFindings_RepeatedCursorTerminates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(configurationFindingEnvelope{
			Items:    []ConfigurationFinding{{ID: "cf_1"}},
			Metadata: PaginationMetadata{NextCursor: "same"},
		})
	}))
	defer srv.Close()

	findings, _, err := newTestClient(srv).SearchConfigurationFindings(
		context.Background(),
		[]ConfigurationFindingFilter{{Field: "status", Operator: "eq", Value: []string{"fail"}}},
		0, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Two pages: the first, then the repeat that stops the loop.
	if len(findings) != 2 {
		t.Errorf("got %d findings, want 2 (loop must stop on a repeated cursor)", len(findings))
	}
}

func TestGetAssetExample(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/v2/organizations/org_test/configurations/asset-examples/aws_s3_bucket"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		// The hyphenated query param is the API's spelling, not Go's.
		if got, want := r.URL.Query().Get("cloud-account-id"), "12345"; got != want {
			t.Errorf("cloud-account-id: got %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"items":[{"name":"bucket-name","isPublic":false,"awsEntity":{"versioning":{"status":"Off"}}}]}`))
	}))
	defer srv.Close()

	raw, err := newTestClient(srv).GetAssetExample(context.Background(), "aws_s3_bucket", "12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The payload must survive as usable JSON with its nesting intact - that shape
	// is the entire value of the endpoint for someone authoring Rego.
	var decoded []map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("returned value is not a JSON array: %v (%s)", err, raw)
	}
	if len(decoded) != 1 || decoded[0]["name"] != "bucket-name" {
		t.Fatalf("unexpected payload: %s", raw)
	}
	if _, ok := decoded[0]["awsEntity"].(map[string]any); !ok {
		t.Errorf("nested awsEntity object was flattened or dropped: %s", raw)
	}
}

// Omitting the account must omit the query param entirely rather than sending an
// empty one, which the API would treat as a real (and unmatched) account filter.
func TestGetAssetExample_NoAccountOmitsQueryParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query string, got %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"items":[{"name":"pod-1"}]}`))
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).GetAssetExample(context.Background(), "kubernetes_pod", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// An unknown asset kind comes back as 200 with an empty items array rather than a
// 404, so it must map onto IsNotFound like every other search-backed read.
func TestGetAssetExample_EmptyItemsIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetAssetExample(context.Background(), "no_such_kind", "")
	if !IsNotFound(err) {
		t.Errorf("IsNotFound: got false, want true (err: %v)", err)
	}
}

// The findings pager is a second copy of the stories pager, so its cap
// arithmetic is verified separately.
func TestSearchConfigurationFindings_MaxResults(t *testing.T) {
	pages := map[string]configurationFindingEnvelope{
		"":   {Items: []ConfigurationFinding{{ID: "cf_1"}, {ID: "cf_2"}}, Metadata: PaginationMetadata{NextCursor: "c2"}},
		"c2": {Items: []ConfigurationFinding{{ID: "cf_3"}, {ID: "cf_4"}}},
	}
	filters := []ConfigurationFindingFilter{{Field: "status", Operator: "eq", Value: []string{"fail"}}}

	cases := map[string]struct {
		maxResults    int
		wantCount     int
		wantTruncated bool
		wantCalls     int
	}{
		"cap inside a page":    {maxResults: 3, wantCount: 3, wantTruncated: true, wantCalls: 2},
		"cap on a boundary":    {maxResults: 2, wantCount: 2, wantTruncated: true, wantCalls: 1},
		"cap equals the total": {maxResults: 4, wantCount: 4, wantTruncated: false, wantCalls: 2},
		"no cap":               {maxResults: 0, wantCount: 4, wantTruncated: false, wantCalls: 2},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				_ = json.NewEncoder(w).Encode(pages[r.URL.Query().Get("cursor")])
			}))
			defer srv.Close()

			findings, truncated, err := newTestClient(srv).SearchConfigurationFindings(
				context.Background(), filters, 2, tc.maxResults)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != tc.wantCount {
				t.Errorf("findings: got %d, want %d", len(findings), tc.wantCount)
			}
			if truncated != tc.wantTruncated {
				t.Errorf("truncated: got %v, want %v", truncated, tc.wantTruncated)
			}
			if calls != tc.wantCalls {
				t.Errorf("requests: got %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}
