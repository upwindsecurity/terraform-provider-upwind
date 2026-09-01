package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const skillsPath = "/threats/skills"

// Skill mirrors the API threat Agent Skill object: a packaged capability an agent
// can load. Name doubles as the download path segment.
type Skill struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version,omitempty"`
}

type skillEnvelope struct {
	Items []Skill `json:"items"`
}

// ListSkills returns every published threat Agent Skill.
//
// GET /threats/skills/{skill-name} is deliberately not wrapped. It
// returns an application/zip binary, which has no useful representation in
// Terraform state - a data source cannot hand a practitioner a zip. Skill
// metadata is what a config can reference; the download stays a CLI concern.
func (c *Client) ListSkills(ctx context.Context) ([]Skill, error) {
	body, err := c.doRequest(ctx, http.MethodGet, skillsPath, nil)
	if err != nil {
		return nil, err
	}

	var env skillEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding skills response: %w", err)
	}
	return env.Items, nil
}

// GetSkill returns one skill by name. There is no metadata endpoint for a single
// skill - only the zip download - so this filters the list.
func (c *Client) GetSkill(ctx context.Context, name string) (*Skill, error) {
	skills, err := c.ListSkills(ctx)
	if err != nil {
		return nil, err
	}
	for i := range skills {
		if skills[i].Name == name {
			return &skills[i], nil
		}
	}
	return nil, fmt.Errorf("threat agent skill %q: %w", name, ErrNotFound)
}
