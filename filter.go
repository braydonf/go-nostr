package nostr

import (
	"encoding/json"

	"golang.org/x/exp/slices"
)

type Filters []Filter

type Filter struct {
	IDs     []string   `json:"ids,omitempty"`
	Kinds   []int      `json:"kinds,omitempty"`
	Authors []string   `json:"authors,omitempty"`
	Tags    TagMap     `json:"-,omitempty"`
	Since   *Timestamp `json:"since,omitempty"`
	Until   *Timestamp `json:"until,omitempty"`
	Limit   int        `json:"limit,omitempty"`
	Search  string     `json:"search,omitempty"`
}

type TagMap map[string][]string

func (eff Filters) String() string {
	j, _ := json.Marshal(eff)
	return string(j)
}

func (eff Filters) Match(event *Event) bool {
	for _, filter := range eff {
		if filter.Matches(event) {
			return true
		}
	}
	return false
}

func (ef Filter) String() string {
	j, _ := json.Marshal(ef)
	return string(j)
}

func (ef Filter) Matches(event *Event) bool {
	if event == nil {
		return false
	}

	if ef.IDs != nil && !slices.Contains(ef.IDs, event.ID) {
		return false
	}

	if ef.Kinds != nil && !slices.Contains(ef.Kinds, event.Kind) {
		return false
	}

	if ef.Authors != nil && !slices.Contains(ef.Authors, event.PubKey) {
		return false
	}

	for f, v := range ef.Tags {
		if v != nil && !event.Tags.ContainsAny(f, v) {
			return false
		}
	}

	if ef.Since != nil && event.CreatedAt < *ef.Since {
		return false
	}

	if ef.Until != nil && event.CreatedAt > *ef.Until {
		return false
	}

	return true
}

func FilterEqual(a Filter, b Filter) bool {
	if !similar(a.Kinds, b.Kinds) {
		return false
	}

	if !similar(a.IDs, b.IDs) {
		return false
	}

	if !similar(a.Authors, b.Authors) {
		return false
	}

	if len(a.Tags) != len(b.Tags) {
		return false
	}

	for f, av := range a.Tags {
		if bv, ok := b.Tags[f]; !ok {
			return false
		} else {
			if !similar(av, bv) {
				return false
			}
		}
	}

	if !arePointerValuesEqual(a.Since, b.Since) {
		return false
	}

	if !arePointerValuesEqual(a.Until, b.Until) {
		return false
	}

	if a.Search != b.Search {
		return false
	}

	return true
}

func (ef Filter) Clone() Filter {
	clone := Filter{
		IDs:     slices.Clone(ef.IDs),
		Authors: slices.Clone(ef.Authors),
		Kinds:   slices.Clone(ef.Kinds),
		Limit:   ef.Limit,
		Search:  ef.Search,
	}

	if ef.Tags != nil {
		clone.Tags = make(TagMap, len(ef.Tags))
		for k, v := range ef.Tags {
			clone.Tags[k] = slices.Clone(v)
		}
	}

	if ef.Since != nil {
		since := *ef.Since
		clone.Since = &since
	}

	if ef.Until != nil {
		until := *ef.Until
		clone.Until = &until
	}

	return clone
}
