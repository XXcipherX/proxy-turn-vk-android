package main

import "testing"

func TestRelayLifecycleReplacesOldGenerationAndRejectsItsLateWorkers(t *testing.T) {
	registry := newRelayLifecycleRegistry(32)
	oldCanceled := 0
	oldOne, ok := registry.RegisterV2("device", "generation-old", "worker-1", func() { oldCanceled++ })
	if !ok {
		t.Fatal("first generation was rejected")
	}
	oldTwo, ok := registry.RegisterV2("device", "generation-old", "worker-2", func() { oldCanceled++ })
	if !ok {
		t.Fatal("second worker in first generation was rejected")
	}

	current, ok := registry.RegisterV2("device", "generation-new", "worker-1", func() {})
	if !ok {
		t.Fatal("new generation was rejected")
	}
	if oldCanceled != 2 {
		t.Fatalf("old generation cancellations = %d, want 2", oldCanceled)
	}
	if late, accepted := registry.RegisterV2("device", "generation-old", "worker-3", func() {}); accepted || late != nil {
		t.Fatal("late worker from retired generation was accepted")
	}

	oldOne.Release()
	oldTwo.Release()
	current.Release()
	stats := registry.Stats()
	if stats.V2Replaced != 2 || stats.V2StaleDenied != 1 {
		t.Fatalf("stats = %+v, want two replacements and one stale denial", stats)
	}
}

func TestRelayLifecycleReplacesDuplicateWorkerOnly(t *testing.T) {
	registry := newRelayLifecycleRegistry(32)
	firstCanceled := 0
	first, ok := registry.RegisterV2("device", "generation", "worker", func() { firstCanceled++ })
	if !ok {
		t.Fatal("first worker was rejected")
	}
	second, ok := registry.RegisterV2("device", "generation", "worker", func() {})
	if !ok {
		t.Fatal("replacement worker was rejected")
	}
	if firstCanceled != 1 {
		t.Fatalf("first worker cancellations = %d, want 1", firstCanceled)
	}

	first.Release()
	second.Release()
	if got := registry.Stats().V2Replaced; got != 1 {
		t.Fatalf("replacements = %d, want 1", got)
	}
}

func TestRelayLifecycleLegacyLimitEvictsOldestConnection(t *testing.T) {
	registry := newRelayLifecycleRegistry(2)
	canceled := []int{}
	first := registry.RegisterLegacy("ios-device", func() { canceled = append(canceled, 1) })
	second := registry.RegisterLegacy("ios-device", func() { canceled = append(canceled, 2) })
	third := registry.RegisterLegacy("ios-device", func() { canceled = append(canceled, 3) })

	if len(canceled) != 1 || canceled[0] != 1 {
		t.Fatalf("canceled = %v, want oldest connection only", canceled)
	}
	if got := registry.Stats().LegacyEvicted; got != 1 {
		t.Fatalf("legacy evictions = %d, want 1", got)
	}

	first.Release()
	second.Release()
	third.Release()
}

func TestRelayLifecycleKeepsLegacyOutsideV2GenerationChanges(t *testing.T) {
	registry := newRelayLifecycleRegistry(2)
	legacyCanceled := 0
	legacy := registry.RegisterLegacy("device", func() { legacyCanceled++ })
	v2, ok := registry.RegisterV2("device", "generation", "worker", func() {})
	if !ok {
		t.Fatal("v2 worker was rejected")
	}
	if legacyCanceled != 0 {
		t.Fatal("v2 registration canceled a legacy connection")
	}

	legacy.Release()
	v2.Release()
}
