package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetStory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/v2/organizations/org_test/threats/stories/story_1"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		_ = json.NewEncoder(w).Encode(storyEnvelope{Items: []Story{{
			ID: "story_1", Title: "Lateral movement", Description: "detail",
			Severity: "CRITICAL", Status: "ARCHIVED", StatusReason: "Accepted Risk",
			DetectionIDs: []string{"det_1", "det_2"},
		}}})
	}))
	defer srv.Close()

	s, err := newTestClient(srv).GetStory(context.Background(), "story_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The singular GET is the only endpoint returning these two fields.
	if s.Description != "detail" || s.StatusReason != "Accepted Risk" {
		t.Errorf("expected description and status_reason to be populated, got %+v", s)
	}
	if len(s.DetectionIDs) != 2 {
		t.Errorf("detection_ids: got %v", s.DetectionIDs)
	}
}

// A missing story must satisfy IsNotFound so the data source can report a clean
// config error rather than a decode failure.
func TestGetStory_EmptyItemsIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(storyEnvelope{Items: []Story{}})
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetStory(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound: got false, want true (err: %v)", err)
	}
}

// ListStories must follow next_cursor to exhaustion: a data source that returned
// only the first page would silently under-report.
func TestListStories_FollowsPagination(t *testing.T) {
	var calls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		cursor := r.URL.Query().Get("cursor")
		switch cursor {
		case "":
			_ = json.NewEncoder(w).Encode(storyEnvelope{
				Items:    []Story{{ID: "s1"}, {ID: "s2"}},
				Metadata: PaginationMetadata{NextCursor: "page2"},
			})
		case "page2":
			_ = json.NewEncoder(w).Encode(storyEnvelope{
				Items:    []Story{{ID: "s3"}},
				Metadata: PaginationMetadata{}, // no next_cursor -> last page
			})
		default:
			t.Errorf("unexpected cursor %q", cursor)
		}
	}))
	defer srv.Close()

	stories, truncated, err := newTestClient(srv).ListStories(context.Background(), nil, 2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 requests, got %d", calls)
	}
	if len(stories) != 3 {
		t.Fatalf("expected 3 stories across both pages, got %d", len(stories))
	}
	if truncated {
		t.Error("truncated: got true, want false - no max_results was set")
	}
	if stories[2].ID != "s3" {
		t.Errorf("last story: got %q, want %q", stories[2].ID, "s3")
	}
}

// A server that echoes the same cursor back must not loop forever.
func TestListStories_RepeatedCursorTerminates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(storyEnvelope{
			Items:    []Story{{ID: "s1"}},
			Metadata: PaginationMetadata{NextCursor: r.URL.Query().Get("cursor")},
		})
	}))
	defer srv.Close()

	stories, _, err := newTestClient(srv).ListStories(context.Background(), nil, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stories) != 1 {
		t.Errorf("expected termination after one page, got %d stories", len(stories))
	}
}

// The stories search endpoint rejects an empty conditions list with a 400, so an
// unfiltered read must go to the plain list endpoint instead. This pins the
// endpoint choice: sending POST /search with no conditions is a live 400.
func TestListStories_UnfilteredUsesListEndpoint(t *testing.T) {
	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewEncoder(w).Encode(storyEnvelope{Items: []Story{{ID: "s1"}}})
	}))
	defer srv.Close()

	if _, _, err := newTestClient(srv).ListStories(context.Background(), nil, 0, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method: got %s, want GET", gotMethod)
	}
	if want := "/v2/organizations/org_test/threats/stories"; gotPath != want {
		t.Errorf("path: got %s, want %s (never /search when unfiltered)", gotPath, want)
	}
}

func TestListStories_SendsFilters(t *testing.T) {
	var body searchRequest

	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(storyEnvelope{Items: []Story{{ID: "s1"}}})
	}))
	defer srv.Close()

	_, _, err := newTestClient(srv).ListStories(context.Background(), []StoryFilter{
		{Field: "status", Operator: "eq", Value: []string{"OPEN"}},
	}, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body.Conditions) != 1 || body.Conditions[0].Field != "status" {
		t.Errorf("conditions: got %+v", body.Conditions)
	}
	// A filtered read must use the search endpoint, and must never send an empty
	// conditions list, which the API rejects with a 400.
	if gotMethod != http.MethodPost || gotPath != "/v2/organizations/org_test/threats/stories/search" {
		t.Errorf("filtered read: got %s %s, want POST .../stories/search", gotMethod, gotPath)
	}
}

// --- skills ---

func TestListSkills(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/v2/organizations/org_test/threats/skills"; got != want {
			t.Errorf("path: got %s, want %s", got, want)
		}
		_ = json.NewEncoder(w).Encode(skillEnvelope{Items: []Skill{
			{Name: "threat-policy-manager", Description: "manages policies", Version: "1.0"},
			{Name: "other-skill", Description: "does other things", Version: "2.1"},
		}})
	}))
	defer srv.Close()

	skills, err := newTestClient(srv).ListSkills(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(skills) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(skills))
	}
}

// GetSkill filters the list, since no per-skill metadata endpoint exists - the
// only single-skill route returns a zip.
func TestGetSkill_FiltersTheList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(skillEnvelope{Items: []Skill{
			{Name: "threat-policy-manager", Version: "1.0"},
			{Name: "other-skill", Version: "2.1"},
		}})
	}))
	defer srv.Close()

	c := newTestClient(srv)

	got, err := c.GetSkill(context.Background(), "other-skill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != "2.1" {
		t.Errorf("version: got %q, want %q", got.Version, "2.1")
	}

	_, err = c.GetSkill(context.Background(), "nope")
	if !IsNotFound(err) {
		t.Errorf("missing skill: IsNotFound got false, want true (err: %v)", err)
	}
}

// Pins the cap's arithmetic: it must stop the paging, report truncation, and not
// report it when the last item lands exactly on the cap.
func TestListStories_MaxResults(t *testing.T) {
	// Three pages of two, six stories in all.
	pages := map[string]storyEnvelope{
		"":   {Items: []Story{{ID: "s1"}, {ID: "s2"}}, Metadata: PaginationMetadata{NextCursor: "c2"}},
		"c2": {Items: []Story{{ID: "s3"}, {ID: "s4"}}, Metadata: PaginationMetadata{NextCursor: "c3"}},
		"c3": {Items: []Story{{ID: "s5"}, {ID: "s6"}}},
	}

	cases := map[string]struct {
		maxResults    int
		wantCount     int
		wantTruncated bool
		wantCalls     int
	}{
		"cap inside a page":      {maxResults: 3, wantCount: 3, wantTruncated: true, wantCalls: 2},
		"cap on a page boundary": {maxResults: 4, wantCount: 4, wantTruncated: true, wantCalls: 2},
		"cap equals the total":   {maxResults: 6, wantCount: 6, wantTruncated: false, wantCalls: 3},
		"cap above the total":    {maxResults: 100, wantCount: 6, wantTruncated: false, wantCalls: 3},
		"no cap":                 {maxResults: 0, wantCount: 6, wantTruncated: false, wantCalls: 3},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				_ = json.NewEncoder(w).Encode(pages[r.URL.Query().Get("cursor")])
			}))
			defer srv.Close()

			stories, truncated, err := newTestClient(srv).ListStories(context.Background(), nil, 2, tc.maxResults)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(stories) != tc.wantCount {
				t.Errorf("stories: got %d, want %d", len(stories), tc.wantCount)
			}
			if truncated != tc.wantTruncated {
				t.Errorf("truncated: got %v, want %v", truncated, tc.wantTruncated)
			}
			// The cap must stop the paging, not just trim what was fetched.
			if calls != tc.wantCalls {
				t.Errorf("requests: got %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

// With no explicit page size, the cap becomes the page size.
func TestListStories_MaxResultsBecomesThePageSize(t *testing.T) {
	var gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.URL.Query().Get("limit")
		_ = json.NewEncoder(w).Encode(storyEnvelope{Items: []Story{{ID: "s1"}}})
	}))
	defer srv.Close()

	if _, _, err := newTestClient(srv).ListStories(context.Background(), nil, 0, 25); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLimit != "25" {
		t.Errorf("limit query param: got %q, want %q", gotLimit, "25")
	}
}
