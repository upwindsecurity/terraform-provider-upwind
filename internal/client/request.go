package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/oauth2"
)

// orgPath builds the full org-scoped URL, e.g.
// https://api.upwind.io/v2/organizations/org_abc/access-management/scopes/scope_1
func (c *Client) orgPath(path string) string {
	return fmt.Sprintf("%s/v2/organizations/%s%s", c.baseURL, c.orgID, path)
}

// AuthError reports a failure to obtain an OAuth2 access token.
//
// It exists to keep the token endpoint's response away from the Terraform user.
// golang.org/x/oauth2 renders a rejected token exchange by embedding the
// verbatim upstream body in the error string, and that body carries Upwind's
// internal identity-provider hostname. Terraform prints a provider error to
// whoever ran the plan, so that string is customer-facing output.
//
// Only the HTTP status is retained. oauth2's parsed ErrorDescription and
// ErrorURI are deliberately dropped as well: on an RFC 6749-shaped response they
// are exactly where an upstream detail would land.
//
// This covers a token endpoint that answered and refused. A token exchange that
// fails at the transport layer (endpoint down, egress blocked) is not an
// *oauth2.RetrieveError and does not arrive here - it stays a wrapped network
// error naming auth.upwind.io, which is public, documented in SECURITY.md, and
// more useful to the reader than a generic auth message would be.
type AuthError struct {
	// StatusCode is the token endpoint's HTTP status. 0 only if oauth2 ever
	// reports a retrieve failure with no response attached, which it does not
	// today; the branch exists so a future change cannot produce "status 0".
	StatusCode int

	// errorCode is RFC 6749's `error` parameter, e.g. "invalid_client". It is
	// only ever compared, never rendered, and stays unexported so no caller can
	// print it by accident: the RFC bounds it to an enum, but it is still
	// upstream-controlled text and a non-conformant endpoint could put anything
	// in it. Comparing is safe; echoing would reopen the hole this type closes.
	errorCode string
}

// credentialHint names every input that can make the token endpoint refuse, and
// both ways each one can be supplied. The provider block takes precedence over
// the environment variable, so an operator who exported the right secret can
// still be authenticating with a stale literal in HCL.
//
// region belongs here with the credentials: client.New derives the token's
// `audience` from it, so a client provisioned for one region is refused when
// pointed at another. The repository's own troubleshooting table already records
// that a 401/403 means "credentials wrong, or UPWIND_REGION does not match the
// organization's region" - naming only the credentials sends that operator
// looking in the wrong place.
const credentialHint = "Check the client_id, client_secret and region provider attributes, " +
	"or the UPWIND_CLIENT_ID, UPWIND_CLIENT_SECRET and UPWIND_REGION environment variables."

func (e *AuthError) Error() string {
	switch {
	case e.isCredentialRejection():
		return "Authentication with Upwind failed: the client credentials were rejected. " + credentialHint
	case e.StatusCode == 0:
		// No status to report, so the credentials cannot be blamed either.
		return "Authentication with Upwind failed: the token request did not return a usable response."
	default:
		// A 5xx or an unexpected status is Upwind's problem, not the operator's;
		// naming the credentials here would be actively misleading.
		return fmt.Sprintf(
			"Authentication with Upwind failed: the token endpoint returned status %d. "+
				"This is usually transient - retry, and contact Upwind support if it persists.",
			e.StatusCode)
	}
}

// isCredentialRejection reports whether the endpoint refused what it was given,
// as opposed to failing for something the operator cannot fix.
//
// Status alone is not enough. RFC 6749 §5.2 makes 400 the default rejection
// status and permits 401 only when the client authenticated through the
// Authorization header; client.New sets AuthStyleInParams, so the credentials
// travel in the form body and a conformant endpoint answers 400. Upwind's
// answers 401 today. Classifying on 401 alone would tell anyone hitting the
// standards-correct 400 to retry a request that can never succeed.
//
// The RFC `error` code is checked first because it states the cause directly,
// whatever status carries it.
func (e *AuthError) isCredentialRejection() bool {
	switch e.errorCode {
	case "invalid_client", "unauthorized_client", "invalid_grant":
		return true
	case "invalid_request", "unsupported_grant_type":
		// A malformed token request is this provider's bug, not a bad credential.
		return false
	}
	switch e.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}

// APIError describes a non-2xx response from the Upwind API.
type APIError struct {
	StatusCode int
	Method     string
	URL        string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("upwind API %s %s: status %d: %s", e.Method, e.URL, e.StatusCode, e.Body)
}

// ErrNotFound marks a resource that does not exist but whose absence the API
// does not report as a 404. Search-backed reads are the case: a missing object
// comes back as 200 with an empty items array, so the client raises this instead.
var ErrNotFound = errors.New("upwind: resource not found")

// IsNotFound reports whether err means "this resource does not exist": either an
// *APIError with a 404 status, or ErrNotFound. Resources use this in Read to drop
// a deleted resource from state instead of erroring.
func IsNotFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// doRequest sends an authenticated request and returns the raw response body.
// The OAuth token is attached automatically by the underlying HTTP client.
// reqBody, when non-nil, is JSON-encoded. Non-2xx responses return an *APIError.
func (c *Client) doRequest(ctx context.Context, method, path string, reqBody any) ([]byte, error) {
	var body io.Reader
	if reqBody != nil {
		encoded, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	url := c.orgPath(path)
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// This is the single choke point for every API call, so logging here covers
	// every resource and data source without repeating itself in each one. The
	// framework already stamps tf_rpc, tf_resource_type / tf_data_source_type and
	// tf_req_id onto ctx, so these lines say which operation the call belongs to.
	//
	// Deliberately not logged: the Authorization header (attached downstream by
	// the OAuth transport) and request/response bodies, which carry tenant data.
	// A failing call's response body still reaches the user through APIError.
	ctx = tflog.SetField(ctx, "http_method", method)
	ctx = tflog.SetField(ctx, "http_url", url)
	tflog.Debug(ctx, "Sending request to the Upwind API")

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		// The OAuth transport fetches and refreshes the token inside Do, so a
		// rejected credential surfaces here as an error rather than as a response.
		// Replace it outright instead of wrapping: %w would carry oauth2's raw
		// rendering, upstream body and all, into the Terraform diagnostic.
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) {
			authErr := &AuthError{errorCode: retrieveErr.ErrorCode}
			if retrieveErr.Response != nil {
				authErr.StatusCode = retrieveErr.Response.StatusCode
			}
			// Status only. The body is the leak, so it is kept out of the log too -
			// TF_LOG output is still something an operator pastes into a ticket, and
			// the package already promises never to log request or response bodies.
			tflog.Debug(ctx, "Upwind token request failed", map[string]any{
				"duration_ms":       time.Since(start).Milliseconds(),
				"token_http_status": authErr.StatusCode,
			})
			return nil, authErr
		}
		tflog.Debug(ctx, "Upwind API request failed before a response", map[string]any{
			"duration_ms": time.Since(start).Milliseconds(),
			"error":       err.Error(),
		})
		return nil, fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s %s: %w", method, url, err)
	}

	fields := map[string]any{
		"http_status":    resp.StatusCode,
		"response_bytes": len(respBody),
		"duration_ms":    time.Since(start).Milliseconds(),
	}
	// Correlation id, when the API sends one: the fastest way for support to find
	// the server side of a failed call. Omitted rather than logged empty.
	if reqID := resp.Header.Get("X-Request-Id"); reqID != "" {
		fields["upwind_request_id"] = reqID
	}
	tflog.Debug(ctx, "Received response from the Upwind API", fields)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{StatusCode: resp.StatusCode, Method: method, URL: url, Body: string(respBody)}
	}
	return respBody, nil
}
