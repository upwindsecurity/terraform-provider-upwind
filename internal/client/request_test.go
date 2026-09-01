package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDoRequest_SendsUserAgent checks the header actually reaches the wire, not
// just that UserAgent() formats a string: the provider is identified to the API
// on every call, so a dropped header is a silent loss of attribution.
func TestDoRequest_SendsUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newClient(srv.Client(), srv.URL, "org_test", UserAgent("1.2.0"))
	if _, err := c.doRequest(context.Background(), http.MethodGet, "/anything", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "terraform-provider-upwind/1.2.0"; got != want {
		t.Errorf("User-Agent: got %q, want %q", got, want)
	}
}

// A build with no injected version must still identify itself.
func TestDoRequest_SendsDevUserAgentForLocalBuild(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newClient(srv.Client(), srv.URL, "org_test", UserAgent(""))
	if _, err := c.doRequest(context.Background(), http.MethodPost, "/anything", map[string]string{"a": "b"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "terraform-provider-upwind/dev"; got != want {
		t.Errorf("User-Agent: got %q, want %q", got, want)
	}
}
