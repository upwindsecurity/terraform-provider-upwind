package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

const storiesPath = "/threats/stories"

// Story mirrors the API threat story object. Stories are platform-generated, so
// there is no create endpoint and the provider exposes them read-only.
//
// Note the list/search endpoints return a SUBSET of the fields the singular GET
// returns: description and status_reason are absent from collection responses.
// A data source built on the collection must leave those null rather than
// guessing, or fetch each story individually.
type Story struct {
	ID           string   `json:"id,omitempty"`
	Title        string   `json:"title,omitempty"`
	Description  string   `json:"description,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Status       string   `json:"status,omitempty"`
	StatusReason string   `json:"status_reason,omitempty"`
	DetectionIDs []string `json:"detection_ids,omitempty"`
	CreateTime   string   `json:"create_time,omitempty"`
	UpdateTime   string   `json:"update_time,omitempty"`
}

// PaginationMetadata is the cursor envelope shared by every paginated v2 endpoint.
type PaginationMetadata struct {
	Limit          int    `json:"limit,omitempty"`
	NextCursor     string `json:"next_cursor,omitempty"`
	PreviousCursor string `json:"previous_cursor,omitempty"`
}

type storyEnvelope struct {
	Items    []Story            `json:"items"`
	Metadata PaginationMetadata `json:"metadata"`
}

// StoryFilter is one condition for SearchStories. Supported fields are severity,
// status, create_time, and update_time; supported operators are eq, in, gte, lte.
type StoryFilter struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Value    []string `json:"value"`
}

// GetStory fetches a single story by id. This is the only endpoint that returns
// description and status_reason.
func (c *Client) GetStory(ctx context.Context, id string) (*Story, error) {
	body, err := c.doRequest(ctx, http.MethodGet, storiesPath+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	var env storyEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding story response: %w", err)
	}
	if len(env.Items) == 0 {
		return nil, fmt.Errorf("story %q: %w", id, ErrNotFound)
	}
	return &env.Items[0], nil
}

// ListStories returns the stories matching the given filters, paging until the
// results run out or maxResults is reached. No filters matches all stories.
//
// pageSize tunes the fetch; maxResults caps what comes back, and with it the
// size of the Terraform state, since every story returned is written there.
// Zero means unlimited for both. The second return value reports truncation:
// a caller that counts results has no other way to tell.
func (c *Client) ListStories(ctx context.Context, filters []StoryFilter, pageSize, maxResults int) ([]Story, bool, error) {
	// Never ask for more than the cap; unset, it makes a small cap one round trip.
	if maxResults > 0 && (pageSize == 0 || pageSize > maxResults) {
		pageSize = maxResults
	}

	var all []Story
	cursor := ""

	for {
		q := url.Values{}
		if pageSize > 0 {
			q.Set("limit", strconv.Itoa(pageSize))
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}

		// Endpoint choice is not cosmetic: the search endpoint rejects an empty
		// conditions list with a 400 ("Field 'conditions': must not be empty"),
		// even though the spec does not mark it required. So unfiltered reads must
		// use the plain list endpoint, which is what it exists for. Both accept the
		// same pagination query params.
		method, path := http.MethodGet, storiesPath
		var reqBody any
		if len(filters) > 0 {
			method, path = http.MethodPost, storiesPath+"/search"
			reqBody = searchRequest{Conditions: toSearchConditions(filters)}
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}

		body, err := c.doRequest(ctx, method, path, reqBody)
		if err != nil {
			return nil, false, err
		}

		var env storyEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			return nil, false, fmt.Errorf("decoding story search response: %w", err)
		}
		all = append(all, env.Items...)

		// Before the cursor, so the cap stops the paging rather than trimming what
		// was already paid for. Exactly maxResults with no next page is complete.
		if maxResults > 0 && len(all) >= maxResults {
			return all[:maxResults], len(all) > maxResults || env.Metadata.NextCursor != "", nil
		}

		// An absent next_cursor means this was the last page. Guard against a
		// server that echoes the same cursor back, which would loop forever.
		if env.Metadata.NextCursor == "" || env.Metadata.NextCursor == cursor {
			return all, false, nil
		}
		cursor = env.Metadata.NextCursor
	}
}

// toSearchConditions converts story filters into the generic search condition
// shape. Only ever called with a non-empty slice: an empty conditions list is
// rejected by the API, so callers use the plain list endpoint instead.
func toSearchConditions(filters []StoryFilter) []searchCondition {
	out := make([]searchCondition, 0, len(filters))
	for _, f := range filters {
		out = append(out, searchCondition(f))
	}
	return out
}
