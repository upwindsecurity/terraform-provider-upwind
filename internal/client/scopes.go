package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const scopesPath = "/access-management/scopes"

// Scope mirrors the API ApiScope object. Server-owned fields (id, *_time,
// creator_id) are populated on read; clients set name/description/filters.
type Scope struct {
	ID              string           `json:"id,omitempty"`
	Name            string           `json:"name,omitempty"`
	Description     string           `json:"description,omitempty"`
	ResourceFilters []ResourceFilter `json:"resource_filters,omitempty"`
	CreateTime      string           `json:"create_time,omitempty"`
	UpdateTime      string           `json:"update_time,omitempty"`
	CreatorID       string           `json:"creator_id,omitempty"`
}

// ResourceFilter is one entry in a scope's resource_filters.
type ResourceFilter struct {
	Attribute string   `json:"attribute"`
	Operator  string   `json:"operator"`
	Values    []string `json:"values"`
}

// CreateScopeRequest is the body for POST /scopes. name and resource_filters
// are required by the API; description is optional.
type CreateScopeRequest struct {
	Name            string           `json:"name"`
	Description     string           `json:"description,omitempty"`
	ResourceFilters []ResourceFilter `json:"resource_filters"`
}

// UpdateScopeRequest is the body for PATCH /scopes/{id}. All fields are optional;
// nil pointers / empty slices are omitted so unspecified fields are left untouched.
type UpdateScopeRequest struct {
	Name            *string          `json:"name,omitempty"`
	Description     *string          `json:"description,omitempty"`
	ResourceFilters []ResourceFilter `json:"resource_filters,omitempty"`
}

// scopeEnvelope is the {items:[...]} wrapper the API returns for scope responses,
// including single-object endpoints (which still return a one-element array).
type scopeEnvelope struct {
	Items []Scope `json:"items"`
}

// GetScope fetches a single scope by id. A missing scope returns an *APIError
// for which IsNotFound reports true.
func (c *Client) GetScope(ctx context.Context, id string) (*Scope, error) {
	body, err := c.doRequest(ctx, http.MethodGet, scopesPath+"/"+id, nil)
	if err != nil {
		return nil, err
	}
	return decodeScope(body)
}

// CreateScope creates a scope and returns it with server-populated fields.
func (c *Client) CreateScope(ctx context.Context, req CreateScopeRequest) (*Scope, error) {
	body, err := c.doRequest(ctx, http.MethodPost, scopesPath, req)
	if err != nil {
		return nil, err
	}
	return decodeScope(body)
}

// UpdateScope applies a partial update (PATCH) and returns the updated scope.
func (c *Client) UpdateScope(ctx context.Context, id string, req UpdateScopeRequest) (*Scope, error) {
	body, err := c.doRequest(ctx, http.MethodPatch, scopesPath+"/"+id, req)
	if err != nil {
		return nil, err
	}
	return decodeScope(body)
}

// DeleteScope removes a scope by id.
func (c *Client) DeleteScope(ctx context.Context, id string) error {
	_, err := c.doRequest(ctx, http.MethodDelete, scopesPath+"/"+id, nil)
	return err
}

// decodeScope unwraps the {items:[scope]} envelope and returns the single scope.
func decodeScope(body []byte) (*Scope, error) {
	var env scopeEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding scope response: %w", err)
	}
	if len(env.Items) == 0 {
		return nil, fmt.Errorf("scope response contained no items")
	}
	return &env.Items[0], nil
}
