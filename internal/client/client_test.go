package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/oauth2"
)

func TestNew_RegionToBaseURL(t *testing.T) {
	cases := map[string]string{
		"us": "https://api.upwind.io",
		"eu": "https://api.eu.upwind.io",
		"me": "https://api.me.upwind.io",
	}
	for region, wantURL := range cases {
		t.Run(region, func(t *testing.T) {
			c, err := New(context.Background(), Config{
				Region: region, OrgID: "org_x", ClientID: "id", ClientSecret: "secret",
			})
			if err != nil {
				t.Fatalf("unexpected error for region %q: %v", region, err)
			}
			if c.BaseURL() != wantURL {
				t.Errorf("region %q: got base URL %q, want %q", region, c.BaseURL(), wantURL)
			}
		})
	}
}

func TestNew_InvalidRegion(t *testing.T) {
	_, err := New(context.Background(), Config{
		Region: "moon", OrgID: "org_x", ClientID: "id", ClientSecret: "secret",
	})
	if err == nil {
		t.Fatal("expected an error for an invalid region, got nil")
	}
}

func TestUserAgent(t *testing.T) {
	cases := map[string]string{
		// A release build injects the version via -ldflags.
		"1.2.0": "terraform-provider-upwind/1.2.0",
		// main.version defaults to "dev" locally, but an empty string can still
		// reach here (a caller that builds Config by hand), so it must not
		// produce a trailing-slash User-Agent.
		"dev": "terraform-provider-upwind/dev",
		"":    "terraform-provider-upwind/dev",
	}
	for version, want := range cases {
		if got := UserAgent(version); got != want {
			t.Errorf("UserAgent(%q): got %q, want %q", version, got, want)
		}
	}
}

func TestNew_SetsUserAgentFromProviderVersion(t *testing.T) {
	c, err := New(context.Background(), Config{
		Region: "us", OrgID: "org_x", ClientID: "id", ClientSecret: "secret",
		ProviderVersion: "9.9.9",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := c.userAgent, "terraform-provider-upwind/9.9.9"; got != want {
		t.Errorf("userAgent: got %q, want %q", got, want)
	}
}

func TestBaseURLAndAudience_EndpointOverridesRegion(t *testing.T) {
	// The endpoint moves the audience too: a token minted for api.upwind.io is
	// refused by any other host.
	got, err := baseURLAndAudience(Config{Region: "us", Endpoint: "https://api.staging.upwind.io/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The trailing slash is trimmed - orgPath concatenates onto this.
	if want := "https://api.staging.upwind.io"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBaseURLAndAudience_EndpointMakesRegionIrrelevant(t *testing.T) {
	// Region is not consulted at all once Endpoint is set, so an absent or
	// unknown one must not fail the build.
	if _, err := baseURLAndAudience(Config{Region: "", Endpoint: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBaseURLAndAudience_RejectsUnusableEndpoint(t *testing.T) {
	// A bare host is the case that matters: url.Parse accepts it as a path.
	for _, endpoint := range []string{
		"api.staging.upwind.io", // no scheme
		"ftp://api.upwind.io",   // not http(s)
		"https://",              // no host
		"://nope",               // unparseable
	} {
		if _, err := baseURLAndAudience(Config{Region: "us", Endpoint: endpoint}); err == nil {
			t.Errorf("endpoint %q: expected an error, got nil", endpoint)
		}
	}
}

func TestNew_EndpointOverridesBaseURL(t *testing.T) {
	c, err := New(context.Background(), Config{
		Region: "us", OrgID: "org_x", ClientID: "id", ClientSecret: "secret",
		Endpoint: "https://api.staging.upwind.io",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "https://api.staging.upwind.io"; c.BaseURL() != want {
		t.Errorf("got base URL %q, want %q", c.BaseURL(), want)
	}
}

// Guards New's one assumption about oauth2: that it reuses the Transport of the
// client under oauth2.HTTPClient. If that changes, retries and the timeout
// vanish from every API call and nothing else notices.
func TestNew_APICallsGoThroughTheRetryingTransport(t *testing.T) {
	c, err := New(context.Background(), Config{
		Region: "us", OrgID: "org_x", ClientID: "id", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	oauthTransport, ok := c.http.Transport.(*oauth2.Transport)
	if !ok {
		t.Fatalf("expected an *oauth2.Transport, got %T", c.http.Transport)
	}
	rt, ok := oauthTransport.Base.(*retryablehttp.RoundTripper)
	if !ok {
		t.Fatalf("expected the oauth transport's base to be a *retryablehttp.RoundTripper, got %T", oauthTransport.Base)
	}
	if got := rt.Client.HTTPClient.Timeout; got != attemptTimeout {
		t.Errorf("per-attempt timeout: got %v, want %v", got, attemptTimeout)
	}
	if got := rt.Client.RetryMax; got != maxRetries {
		t.Errorf("RetryMax: got %d, want %d", got, maxRetries)
	}
}

func TestRetryingHTTPClient_RetriesRateLimitAndServerError(t *testing.T) {
	for name, status := range map[string]int{
		"rate limited": http.StatusTooManyRequests,
		"server error": http.StatusInternalServerError,
	} {
		t.Run(name, func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&calls, 1) == 1 {
					// Honoured verbatim, so the test skips the real 1s backoff.
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			resp, err := retryingHTTPClient().Get(srv.URL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status: got %d, want 200", resp.StatusCode)
			}
			if got := atomic.LoadInt32(&calls); got != 2 {
				t.Errorf("server calls: got %d, want 2 (one failure, one retry)", got)
			}
		})
	}
}

func TestRetryingHTTPClient_DoesNotRetryAClientError(t *testing.T) {
	// A 400 answers the same way every time; retrying only makes it slow.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	resp, err := retryingHTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("server calls: got %d, want 1 (a 4xx must not be retried)", got)
	}
}

// Without the ErrorHandler a 429, 503 and 500 are indistinguishable and
// IsNotFound cannot classify anything.
func TestClient_ExhaustedRetriesKeepTheStatusAndBody(t *testing.T) {
	for name, status := range map[string]int{
		// 503, not 500: Retry-After is honoured on 429 and 503 only, so this
		// skips a 15s backoff.
		"server error": http.StatusServiceUnavailable,
		"rate limited": http.StatusTooManyRequests,
	} {
		t.Run(name, func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"message":"upstream detail"}`))
			}))
			defer srv.Close()

			c := newClient(retryingHTTPClient(), srv.URL, "org_test", "ua")
			_, err := c.doRequest(context.Background(), http.MethodGet, "/whatever", nil)
			if err == nil {
				t.Fatal("expected an error after the retries were exhausted")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected an *APIError, got %T: %v", err, err)
			}
			if apiErr.StatusCode != status {
				t.Errorf("status: got %d, want %d", apiErr.StatusCode, status)
			}
			if !strings.Contains(apiErr.Body, "upstream detail") {
				t.Errorf("body was dropped: %q", apiErr.Body)
			}
			if got := atomic.LoadInt32(&calls); got != maxRetries+1 {
				t.Errorf("attempts: got %d, want %d", got, maxRetries+1)
			}
		})
	}
}

func TestRegions_CoversEveryHost(t *testing.T) {
	// A region missing here is accepted by the client and rejected at plan time.
	got := Regions()
	if len(got) != len(regionHosts) {
		t.Fatalf("Regions() returned %d entries, regionHosts has %d", len(got), len(regionHosts))
	}
	for _, r := range got {
		if _, ok := regionHosts[r]; !ok {
			t.Errorf("Regions() reported %q, which regionHosts does not define", r)
		}
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("Regions() must be sorted for a stable schema description, got %v", got)
	}
}
