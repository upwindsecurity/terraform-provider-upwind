// Package client is the Upwind Management REST API v2 client used by the provider.
// It handles regional routing and OAuth2 client-credentials authentication; the
// per-resource request methods (get/search/create/...) are built on top of it in
// the sibling files of this package.
package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// tokenURL is the shared (non-regional) OAuth2 token endpoint. The region is
// pinned via the `audience` parameter, not the token host.
const tokenURL = "https://auth.upwind.io/oauth/token"

// regionHosts maps a region code to its API host. A token's `audience` must
// match the regional host it will be used against, so we derive both from here.
var regionHosts = map[string]string{
	"us": "api.upwind.io",
	"eu": "api.eu.upwind.io",
	"me": "api.me.upwind.io",
	"ap": "api.ap.upwind.io",
}

// Regions returns the supported region codes, sorted. The provider's validator,
// description and error text all read from it rather than restating the list.
func Regions() []string {
	out := make([]string, 0, len(regionHosts))
	for r := range regionHosts {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// Retry and timeout budget, applied to API calls and the token exchange alike.
// attemptTimeout bounds ONE attempt: Terraform sets no deadline on a provider's
// context, so without it a host that accepts and never answers hangs the plan.
const (
	attemptTimeout = 60 * time.Second
	maxRetries     = 4
	retryWaitMin   = 1 * time.Second
	retryWaitMax   = 30 * time.Second
)

// Config holds the inputs needed to construct a Client.
type Config struct {
	Region       string
	OrgID        string
	ClientID     string
	ClientSecret string
	// Endpoint overrides the API base URL derived from Region, for Upwind's own
	// testing against staging. Set only from UPWIND_ENDPOINT - there is no
	// provider attribute for it. Empty means use the region's host.
	Endpoint string
	// ProviderVersion is the provider's build version, used in the User-Agent.
	// Empty means an uninjected local build and is reported as "dev".
	ProviderVersion string
}

// Client talks to the Upwind API for one organization in one region.
type Client struct {
	http      *http.Client
	baseURL   string
	orgID     string
	userAgent string
}

// UserAgent builds the User-Agent sent on every API request, e.g.
// "terraform-provider-upwind/1.2.0". A build without -ldflags version injection
// reports "dev" rather than an empty version.
func UserAgent(providerVersion string) string {
	if providerVersion == "" {
		providerVersion = "dev"
	}
	return "terraform-provider-upwind/" + providerVersion
}

// baseURLAndAudience returns the one value used as both, because they must not
// diverge: a token whose `audience` names a different host than the one it is
// presented to is refused. An Endpoint override therefore moves both, and Region
// is not consulted at all.
//
// Validated here, not by a schema validator: the value can arrive from
// UPWIND_ENDPOINT, and it is the address a bearer token gets sent to.
func baseURLAndAudience(cfg Config) (string, error) {
	if cfg.Endpoint == "" {
		host, ok := regionHosts[cfg.Region]
		if !ok {
			return "", fmt.Errorf("invalid region %q: must be one of %s", cfg.Region, strings.Join(Regions(), ", "))
		}
		return "https://" + host, nil
	}

	base := strings.TrimSuffix(cfg.Endpoint, "/")
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", cfg.Endpoint, err)
	}
	// A bare host parses clean as a scheme-less path, so check the scheme.
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid endpoint %q: must be an absolute URL beginning http:// or https://", cfg.Endpoint)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid endpoint %q: no host", cfg.Endpoint)
	}
	return base, nil
}

// retryingHTTPClient builds the transport every request rides on. The library's
// defaults are what is wanted: retry transport errors, 429 and 5xx except 501;
// exponential backoff; sleep for Retry-After on a 429 or 503; abort on a
// cancelled context. A 4xx other than 429 is deliberately not retried.
func retryingHTTPClient() *http.Client {
	rc := retryablehttp.NewClient()
	rc.RetryMax = maxRetries
	rc.RetryWaitMin = retryWaitMin
	rc.RetryWaitMax = retryWaitMax
	rc.HTTPClient.Timeout = attemptTimeout

	// The default logger writes to stderr, which for a provider is Terraform's
	// own output. Report through tflog instead, which is off without TF_LOG.
	rc.Logger = nil
	rc.RequestLogHook = func(_ retryablehttp.Logger, req *http.Request, attempt int) {
		if attempt == 0 {
			return // doRequest already logs the first try
		}
		tflog.Debug(req.Context(), "Retrying a request to the Upwind API", map[string]any{
			"attempt":     attempt,
			"max_retries": maxRetries,
		})
	}

	// Exhausted retries otherwise discard the last response, so the status and
	// body are lost. Hand it back and doRequest renders an *APIError as usual.
	rc.ErrorHandler = func(resp *http.Response, err error, attempts int) (*http.Response, error) {
		if resp == nil {
			return nil, err // a transport failure has no response to report
		}
		return resp, nil
	}

	return rc.StandardClient()
}

// New builds an authenticated client. It configures an OAuth2 client-credentials
// token source that fetches, caches, and transparently refreshes the bearer
// token; no network call is made here - the first token is requested lazily on
// the first API call.
func New(ctx context.Context, cfg Config) (*Client, error) {
	base, err := baseURLAndAudience(cfg)
	if err != nil {
		return nil, err
	}

	oauthCfg := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenURL,
		// Upwind expects client_id/client_secret as form params (not Basic auth).
		AuthStyle: oauth2.AuthStyleInParams,
		// Pin the token to the API it is presented to.
		EndpointParams: url.Values{"audience": {base}},
	}

	// Detach from the Configure RPC's context: that context is canceled as soon
	// as Configure returns, but the token source must stay alive for the whole
	// provider lifetime - tokens are fetched lazily on the first API call.
	oauthCtx := context.WithoutCancel(ctx)

	// oauth2 uses this client for the token exchange AND reuses its Transport as
	// the base of the client it returns, so one assignment covers both hops. It
	// keeps only the Transport, which is why attemptTimeout is set on
	// retryablehttp's inner client rather than on this wrapper.
	oauthCtx = context.WithValue(oauthCtx, oauth2.HTTPClient, retryingHTTPClient())

	return newClient(oauthCfg.Client(oauthCtx), base, cfg.OrgID, UserAgent(cfg.ProviderVersion)), nil
}

// newClient assembles a Client from an already-built HTTP client. Tests use this
// directly with an httptest server so request logic can be exercised without a
// real OAuth token exchange.
func newClient(httpClient *http.Client, baseURL, orgID, userAgent string) *Client {
	return &Client{http: httpClient, baseURL: baseURL, orgID: orgID, userAgent: userAgent}
}

// BaseURL returns the regional API base, e.g. "https://api.upwind.io".
func (c *Client) BaseURL() string { return c.baseURL }

// OrgID returns the configured organization id.
func (c *Client) OrgID() string { return c.orgID }
