package auth

import (
	"context"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Guards the regression where primaryPriorityBonus leaked into the weight-robin cycle weight
// (queue showed w:1000001 for priority 1) and inflated the cycle by a million slots per model.
func TestWeightedRobinQueueWeightExcludesAntigravityPrimaryBonus(t *testing.T) {
	t.Parallel()

	primary := &Auth{
		ID: "ag-primary", Provider: "antigravity", Status: StatusActive,
		Attributes:  map[string]string{"priority": "1"},
		PrimaryInfo: &PrimaryInfo{IsPrimary: true, Order: 1},
	}
	peer := &Auth{ID: "claude-key", Provider: "claude", Status: StatusActive}
	auths := []*Auth{primary, peer}

	selector := &WeightedRobinSelector{}
	if _, err := selector.Pick(context.Background(), "mixed", "claude-opus-5-5", cliproxyexecutor.Options{}, auths); err != nil {
		t.Fatalf("Pick() error = %v", err)
	}

	snapshot := selector.QueueState("mixed", "claude-opus-5-5", auths)
	if len(snapshot.Entries) != 2 {
		t.Fatalf("queue entries = %d, want 2", len(snapshot.Entries))
	}
	for _, entry := range snapshot.Entries {
		if entry.Weight != 1 {
			t.Errorf("queue weight for %s = %d, want 1 (configured priority, no primary bonus)", entry.AuthID, entry.Weight)
		}
	}
	if snapshot.CycleLength != 2 {
		t.Errorf("cycle length = %d, want 2", snapshot.CycleLength)
	}
	if snapshot.TotalWeight != 2 {
		t.Errorf("total weight = %d, want 2", snapshot.TotalWeight)
	}

	if got := authPriority(primary); got != 1_000_001 {
		t.Errorf("authPriority(primary) = %d, want 1000001", got)
	}
	if got := authPriority(peer); got != 0 {
		t.Errorf("authPriority(peer) = %d, want 0", got)
	}
}

func TestWeightedRobinCycleWeightUsesConfiguredPriorityOnly(t *testing.T) {
	t.Parallel()

	primary := &Auth{
		ID: "ag-primary", Provider: "antigravity", Status: StatusActive,
		PrimaryInfo: &PrimaryInfo{IsPrimary: true, Order: 1},
	}
	weighted := &Auth{
		ID: "claude-key", Provider: "claude", Status: StatusActive,
		Attributes: map[string]string{"priority": "3"},
	}
	auths := []*Auth{primary, weighted}

	selector := &WeightedRobinSelector{}
	if _, err := selector.Pick(context.Background(), "mixed", "claude-opus-5-5", cliproxyexecutor.Options{}, auths); err != nil {
		t.Fatalf("Pick() error = %v", err)
	}

	snapshot := selector.QueueState("mixed", "claude-opus-5-5", auths)
	if snapshot.CycleLength != 4 || snapshot.TotalWeight != 4 {
		t.Fatalf("cycle length/total weight = %d/%d, want 4/4", snapshot.CycleLength, snapshot.TotalWeight)
	}
	weights := map[string]int{}
	for _, entry := range snapshot.Entries {
		weights[entry.AuthID] = entry.Weight
	}
	if weights["ag-primary"] != 1 {
		t.Errorf("primary weight = %d, want 1", weights["ag-primary"])
	}
	if weights["claude-key"] != 3 {
		t.Errorf("weighted peer weight = %d, want 3", weights["claude-key"])
	}
}
