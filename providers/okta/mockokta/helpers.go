package mockokta

import (
	"encoding/json"
	"sort"
)

// jsonItem is anything that marshals to a JSON object.
type jsonItem = any

// rawArray renders items as a JSON array, never null (Okta returns []).
func rawArray(items []jsonItem) []jsonItem {
	if items == nil {
		return []jsonItem{}
	}
	return items
}

// toRaw marshals each item for the paginator.
func toRaw(items []jsonItem) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		b, _ := json.Marshal(it)
		out = append(out, b)
	}
	return out
}

func sortedFactors(m map[string]*Factor) []*Factor {
	out := make([]*Factor, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedRoles(m map[string]*RoleAssignment) []*RoleAssignment {
	out := make([]*RoleAssignment, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedGroups(m map[string]*Group) []*Group {
	out := make([]*Group, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedZones(m map[string]*Zone) []*Zone {
	out := make([]*Zone, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedIdps(m map[string]*IdP) []*IdP {
	out := make([]*IdP, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedApps(m map[string]*App) []*App {
	out := make([]*App, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedPolicies(m map[string]*Policy) []*Policy {
	out := make([]*Policy, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedRules(m map[string]*PolicyRule) []*PolicyRule {
	out := make([]*PolicyRule, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedGrants(m map[string]*AppGrant) []*AppGrant {
	out := make([]*AppGrant, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedCustomRoles(m map[string]*CustomRole) []*CustomRole {
	out := make([]*CustomRole, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedResourceSets(m map[string]*ResourceSet) []*ResourceSet {
	out := make([]*ResourceSet, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedBindings(m map[string]*Binding) []*Binding {
	out := make([]*Binding, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
