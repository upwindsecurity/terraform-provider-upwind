package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// internalDetail stands in for the infrastructure an upstream token endpoint may
// name in its error body. A real rejection identified a service by an internal
// DNS address; that address is deliberately not reproduced here, because a test
// fixture is as public as any other line of code. A synthetic marker exercises
// the same path, since the assertions only check that it never reaches the
// operator.
//
// Do not replace this with the real hostname. That reintroduces the disclosure
// the code under test exists to prevent.
const internalDetail = "id-provider.internal.example"

// The shape the real rejection arrived in: a wrapper message quoting the
// upstream request, with the origin URL embedded in free text.
const upstreamLeakBody = `{"code":"401","message":"401 Unauthorized on POST request for ` +
	`\"http://` + internalDetail + `/realms/REDACTED/protocol/openid-connect/token\": ` +
	`\"{\"error\":\"invalid_client\",\"error_description\":\"Invalid client or Invalid client credentials\"}\""}`

// An RFC 6749-shaped body is the other shape to guard: oauth2 parses
// error_description and error_uri into struct fields and prints them, so a leak
// can arrive through the parsed fields rather than the raw body.
const rfc6749LeakBody = `{"error":"invalid_client",` +
	`"error_description":"rejected by ` + internalDetail + ` realm REDACTED",` +
	`"error_uri":"http://` + internalDetail + `/realms/REDACTED/docs"}`

// The spec-conformant rejection for in-body client authentication: RFC 6749
// §5.2 makes 400 the default status and permits 401 only for Authorization-header
// auth, which the provider does not use.
const rfc6749InvalidClient400 = `{"error":"invalid_client",` +
	`"error_description":"rejected by ` + internalDetail + ` realm REDACTED"}`

// A 400 that is the provider's own bug, not a bad credential.
const rfc6749InvalidRequest400 = `{"error":"invalid_request","error_description":"missing grant_type"}`

const (
	testClientID     = "test-client-id-abc123"
	testClientSecret = "test-client-secret-s3cr3t"
)

// doRequestAgainstTokenEndpoint drives a real oauth2 client-credentials exchange
// against a stub token endpoint, so the test exercises the same error chain the
// provider hits in production (url.Error wrapping oauth2.RetrieveError) rather
// than a hand-built error that might not match.
func doRequestAgainstTokenEndpoint(t *testing.T, status int, body string) error {
	t.Helper()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(tokenSrv.Close)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the API was called even though the token exchange failed")
	}))
	t.Cleanup(apiSrv.Close)

	cfg := &clientcredentials.Config{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		TokenURL:     tokenSrv.URL,
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	c := newClient(cfg.Client(context.Background()), apiSrv.URL, "org_test", UserAgent("1.2.0"))

	_, err := c.doRequest(context.Background(), http.MethodGet, "/anything", nil)
	if err == nil {
		t.Fatal("expected an error from a failed token exchange, got nil")
	}
	return err
}

// forbiddenSubstrings are the things a customer-facing diagnostic must never
// contain: internal infrastructure, oauth2's raw rendering, and the credentials
// themselves.
var forbiddenSubstrings = []string{
	// Whatever the upstream body named must not survive into the diagnostic.
	internalDetail,
	"internal.example",
	"realms",
	"openid-connect",
	"invalid_client",
	"error_description",
	"oauth2: cannot fetch token",
	"Response:",
	testClientID,
	testClientSecret,
}

func assertSanitized(t *testing.T, msg string) {
	t.Helper()
	lower := strings.ToLower(msg)
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(lower, strings.ToLower(bad)) {
			t.Errorf("error message leaks %q:\n%s", bad, msg)
		}
	}
}

// A rejected credential must produce an actionable AuthError, not the upstream
// body. 401 and 403 are both "your credentials are wrong" from the operator's
// point of view.
func TestDoRequest_RejectedCredentialsAreSanitized(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"401 with the real upstream body shape", http.StatusUnauthorized, upstreamLeakBody},
		{"403 with the real upstream body shape", http.StatusForbidden, upstreamLeakBody},
		{"401 with an RFC 6749 body", http.StatusUnauthorized, rfc6749LeakBody},
		{"403 with an RFC 6749 body", http.StatusForbidden, rfc6749LeakBody},
		// The status a conformant endpoint returns for in-body client auth. Before
		// this case existed, a 400 fell through to "usually transient - retry",
		// telling the operator to retry a request that can never succeed.
		{"400 invalid_client, the spec-conformant rejection", http.StatusBadRequest, rfc6749InvalidClient400},
		{"400 with no parseable error code", http.StatusBadRequest, `{"code":"400","message":"bad request"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := doRequestAgainstTokenEndpoint(t, tc.status, tc.body)

			var authErr *AuthError
			if !errors.As(err, &authErr) {
				t.Fatalf("got %T, want *AuthError: %v", err, err)
			}
			if authErr.StatusCode != tc.status {
				t.Errorf("StatusCode: got %d, want %d", authErr.StatusCode, tc.status)
			}

			msg := err.Error()
			assertSanitized(t, msg)

			// Actionable: it has to name what to go and change.
			for _, want := range []string{
				"UPWIND_CLIENT_ID", "UPWIND_CLIENT_SECRET", "UPWIND_REGION",
				"client_id", "client_secret", "region",
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("error message does not mention %q:\n%s", want, msg)
				}
			}
		})
	}
}

// Not every 400 is a bad credential. RFC 6749 `invalid_request` means the
// provider sent a malformed token request - blaming the operator's credentials
// for our own bug is the same misdirection this change set out to remove.
func TestDoRequest_MalformedTokenRequestIsNotBlamedOnCredentials(t *testing.T) {
	err := doRequestAgainstTokenEndpoint(t, http.StatusBadRequest, rfc6749InvalidRequest400)

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("got %T, want *AuthError: %v", err, err)
	}
	msg := err.Error()
	assertSanitized(t, msg)
	if strings.Contains(msg, "UPWIND_CLIENT_ID") {
		t.Errorf("invalid_request is a malformed request, not a rejected credential:\n%s", msg)
	}
}

// The RFC error code is authoritative over the status: an endpoint that says
// invalid_client under an odd status is still a rejected credential.
func TestDoRequest_ErrorCodeOutranksStatus(t *testing.T) {
	err := doRequestAgainstTokenEndpoint(t, http.StatusInternalServerError, rfc6749InvalidClient400)

	msg := err.Error()
	assertSanitized(t, msg)
	if !strings.Contains(msg, "UPWIND_CLIENT_ID") {
		t.Errorf("invalid_client should be read as a rejected credential whatever the status:\n%s", msg)
	}
}

// A token endpoint that is broken rather than rejecting is a different problem:
// still sanitized, but it must not send the operator off checking credentials
// that were never the issue.
func TestDoRequest_TokenEndpointServerErrorIsSanitizedAndNotBlamedOnCredentials(t *testing.T) {
	err := doRequestAgainstTokenEndpoint(t, http.StatusInternalServerError, upstreamLeakBody)

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("got %T, want *AuthError: %v", err, err)
	}
	if authErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode: got %d, want 500", authErr.StatusCode)
	}

	msg := err.Error()
	assertSanitized(t, msg)
	if !strings.Contains(msg, "500") {
		t.Errorf("error message should name the status:\n%s", msg)
	}
	if strings.Contains(msg, "UPWIND_CLIENT_ID") {
		t.Errorf("a 500 is not a credential problem, but the message says to check credentials:\n%s", msg)
	}
}

// A token endpoint that cannot be reached at all fails at the transport layer,
// which oauth2 reports as a plain error rather than a *RetrieveError - so it is
// deliberately NOT an AuthError. This test pins that down, because the opposite
// assumption is easy to make and would be wrong: it documents what an operator
// with blocked egress actually sees, and proves that path leaks nothing either.
func TestDoRequest_UnreachableTokenEndpointIsNotAnAuthErrorButStillLeaksNothing(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing is listening on that port now

	cfg := &clientcredentials.Config{
		ClientID: testClientID, ClientSecret: testClientSecret,
		TokenURL: deadURL, AuthStyle: oauth2.AuthStyleInParams,
	}
	c := newClient(cfg.Client(context.Background()), "http://api.example.invalid", "org_test", UserAgent("1.2.0"))

	_, err := c.doRequest(context.Background(), http.MethodGet, "/anything", nil)
	if err == nil {
		t.Fatal("expected an error when the token endpoint is unreachable")
	}

	var authErr *AuthError
	if errors.As(err, &authErr) {
		t.Error("a transport-level token failure is not an *oauth2.RetrieveError, " +
			"so it should not be reported as an AuthError - if oauth2 changed, " +
			"revisit the AuthError doc comment and its StatusCode 0 branch")
	}
	// The network error names the token URL and the dial failure, which is the
	// useful detail here. What it must not carry is a credential.
	assertSanitized(t, err.Error())
}

// The defensive branch: if a retrieve failure ever arrives with no status, the
// message must not read "status 0" and must not blame the credentials.
func TestAuthError_ZeroStatusIsNotBlamedOnCredentials(t *testing.T) {
	msg := (&AuthError{}).Error()
	assertSanitized(t, msg)
	if strings.Contains(msg, "UPWIND_CLIENT_ID") {
		t.Errorf("with no status the credentials were never assessed:\n%s", msg)
	}
	if strings.Contains(msg, "status 0") {
		t.Errorf("message should not report a meaningless status:\n%s", msg)
	}
}

// The success path. Every other test here drives a failure, so without this one
// a broken oauth2 client construction would leave the whole suite green while no
// call could authenticate at all.
func TestDoRequest_SuccessfulTokenIsAttachedAsBearer(t *testing.T) {
	var tokenCalls int
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenSrv.Close()

	var gotAuth string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer apiSrv.Close()

	cfg := &clientcredentials.Config{
		ClientID: testClientID, ClientSecret: testClientSecret,
		TokenURL: tokenSrv.URL, AuthStyle: oauth2.AuthStyleInParams,
	}
	c := newClient(cfg.Client(context.Background()), apiSrv.URL, "org_test", UserAgent("1.2.0"))

	body, err := c.doRequest(context.Background(), http.MethodGet, "/anything", nil)
	if err != nil {
		t.Fatalf("unexpected error on the success path: %v", err)
	}
	if got, want := gotAuth, "Bearer tok-abc"; got != want {
		t.Errorf("Authorization header: got %q, want %q", got, want)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("response body: got %q", body)
	}

	// The token source caches: a second call must not re-fetch.
	if _, err := c.doRequest(context.Background(), http.MethodGet, "/anything", nil); err != nil {
		t.Fatalf("unexpected error on the second call: %v", err)
	}
	if tokenCalls != 1 {
		t.Errorf("token fetched %d times, want 1 - the token is not being cached", tokenCalls)
	}
}

// Regression guard for the original defect: this exact string is what Terraform
// used to print.
func TestDoRequest_DoesNotEmitOAuth2RawRendering(t *testing.T) {
	err := doRequestAgainstTokenEndpoint(t, http.StatusUnauthorized, upstreamLeakBody)
	if strings.Contains(err.Error(), internalDetail) {
		t.Fatalf("the upstream identity-provider host is still in the diagnostic:\n%s", err.Error())
	}
}

// The sanitizing must be surgical. An authenticated call that reaches the API
// and comes back non-2xx is a different failure, and its body is the tenant's
// own API response - the detail an operator needs. It must still be an APIError
// carrying that body.
func TestDoRequest_APIErrorsKeepTheirBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"Invalid resource values for attribute cloud_account_id"}`))
	}))
	defer srv.Close()

	c := newClient(srv.Client(), srv.URL, "org_test", UserAgent("1.2.0"))
	_, err := c.doRequest(context.Background(), http.MethodPost, "/anything", nil)
	if err == nil {
		t.Fatal("expected an error for a 400 response")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *APIError: %v", err, err)
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		t.Fatal("an API 400 must not be reported as an authentication failure")
	}
	if !strings.Contains(err.Error(), "cloud_account_id") {
		t.Errorf("the API response detail was dropped:\n%s", err.Error())
	}
}

// A 401 from the API itself (not the token endpoint) is an authorization
// problem on a real, authenticated call - a token that is valid but lacks the
// scope. It stays an APIError so IsNotFound and the existing handling are
// unchanged.
func TestDoRequest_APIUnauthorizedIsNotAnAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"insufficient scope"}`))
	}))
	defer srv.Close()

	c := newClient(srv.Client(), srv.URL, "org_test", UserAgent("1.2.0"))
	_, err := c.doRequest(context.Background(), http.MethodGet, "/anything", nil)

	var authErr *AuthError
	if errors.As(err, &authErr) {
		t.Fatal("an API 401 is not a token-retrieval failure and must stay an APIError")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *APIError: %v", err, err)
	}
}
