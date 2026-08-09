package main

import (
	"sync"
	"sync/atomic"
)

const maxRetiredGenerationsPerDevice = 64

type relayLifecycleProtocol uint8

const (
	relayLifecycleLegacy relayLifecycleProtocol = iota + 1
	relayLifecycleV2
)

type relayLifecycleStats struct {
	V2Replaced    int64
	V2StaleDenied int64
	LegacyEvicted int64
}

type relayWorker struct {
	token  uint64
	cancel func()
}

type relayDeviceLifecycle struct {
	currentGeneration string
	workers            map[string]relayWorker
	retiredGenerations map[string]struct{}
	retiredOrder       []string
	legacy             map[uint64]relayWorker
	legacyOrder        []uint64
}

type relayLifecycleRegistry struct {
	mu sync.Mutex

	legacyLimit int
	nextToken   uint64
	devices     map[string]*relayDeviceLifecycle

	v2Replaced    atomic.Int64
	v2StaleDenied atomic.Int64
	legacyEvicted atomic.Int64
}

type relayLifecycleRegistration struct {
	registry     *relayLifecycleRegistry
	protocol     relayLifecycleProtocol
	deviceID     string
	generationID string
	workerID     string
	token        uint64
	once         sync.Once
}

func newRelayLifecycleRegistry(legacyLimit int) *relayLifecycleRegistry {
	return &relayLifecycleRegistry{
		legacyLimit: legacyLimit,
		devices:     make(map[string]*relayDeviceLifecycle),
	}
}

func (r *relayLifecycleRegistry) deviceLocked(deviceID string) *relayDeviceLifecycle {
	state := r.devices[deviceID]
	if state == nil {
		state = &relayDeviceLifecycle{
			workers:            make(map[string]relayWorker),
			retiredGenerations: make(map[string]struct{}),
			legacy:             make(map[uint64]relayWorker),
		}
		r.devices[deviceID] = state
	}
	return state
}

func (r *relayLifecycleRegistry) nextTokenLocked() uint64 {
	r.nextToken++
	return r.nextToken
}

func retireGenerationLocked(state *relayDeviceLifecycle, generationID string) {
	if generationID == "" {
		return
	}
	if _, exists := state.retiredGenerations[generationID]; exists {
		return
	}
	state.retiredGenerations[generationID] = struct{}{}
	state.retiredOrder = append(state.retiredOrder, generationID)
	if len(state.retiredOrder) <= maxRetiredGenerationsPerDevice {
		return
	}
	oldest := state.retiredOrder[0]
	state.retiredOrder = state.retiredOrder[1:]
	delete(state.retiredGenerations, oldest)
}

func runRelayCancellations(cancellations []func()) {
	for _, cancel := range cancellations {
		if cancel != nil {
			cancel()
		}
	}
}

func (r *relayLifecycleRegistry) RegisterV2(deviceID, generationID, workerID string, cancel func()) (*relayLifecycleRegistration, bool) {
	if r == nil {
		return nil, false
	}

	var cancellations []func()
	r.mu.Lock()
	state := r.deviceLocked(deviceID)
	if _, retired := state.retiredGenerations[generationID]; retired {
		r.mu.Unlock()
		r.v2StaleDenied.Add(1)
		return nil, false
	}

	if state.currentGeneration == "" {
		state.currentGeneration = generationID
	} else if state.currentGeneration != generationID {
		retireGenerationLocked(state, state.currentGeneration)
		for _, worker := range state.workers {
			cancellations = append(cancellations, worker.cancel)
		}
		state.workers = make(map[string]relayWorker)
		state.currentGeneration = generationID
	}

	if previous, exists := state.workers[workerID]; exists {
		cancellations = append(cancellations, previous.cancel)
	}
	token := r.nextTokenLocked()
	state.workers[workerID] = relayWorker{token: token, cancel: cancel}
	r.mu.Unlock()

	if len(cancellations) != 0 {
		r.v2Replaced.Add(int64(len(cancellations)))
		runRelayCancellations(cancellations)
	}
	return &relayLifecycleRegistration{
		registry:     r,
		protocol:     relayLifecycleV2,
		deviceID:     deviceID,
		generationID: generationID,
		workerID:     workerID,
		token:        token,
	}, true
}

func (r *relayLifecycleRegistry) RegisterLegacy(deviceID string, cancel func()) *relayLifecycleRegistration {
	if r == nil {
		return nil
	}

	var cancellations []func()
	r.mu.Lock()
	state := r.deviceLocked(deviceID)
	token := r.nextTokenLocked()
	state.legacy[token] = relayWorker{token: token, cancel: cancel}
	state.legacyOrder = append(state.legacyOrder, token)
	for len(state.legacy) > r.legacyLimit && len(state.legacyOrder) != 0 {
		oldest := state.legacyOrder[0]
		state.legacyOrder = state.legacyOrder[1:]
		worker, exists := state.legacy[oldest]
		if !exists {
			continue
		}
		delete(state.legacy, oldest)
		cancellations = append(cancellations, worker.cancel)
	}
	r.mu.Unlock()

	if len(cancellations) != 0 {
		r.legacyEvicted.Add(int64(len(cancellations)))
		runRelayCancellations(cancellations)
	}
	return &relayLifecycleRegistration{
		registry: r,
		protocol: relayLifecycleLegacy,
		deviceID: deviceID,
		token:    token,
	}
}

func removeLegacyToken(order []uint64, token uint64) []uint64 {
	for i, candidate := range order {
		if candidate == token {
			copy(order[i:], order[i+1:])
			return order[:len(order)-1]
		}
	}
	return order
}

func (r *relayLifecycleRegistration) Release() {
	if r == nil || r.registry == nil {
		return
	}
	r.once.Do(func() {
		registry := r.registry
		registry.mu.Lock()
		defer registry.mu.Unlock()

		state := registry.devices[r.deviceID]
		if state == nil {
			return
		}
		switch r.protocol {
		case relayLifecycleV2:
			if state.currentGeneration != r.generationID {
				return
			}
			worker, exists := state.workers[r.workerID]
			if exists && worker.token == r.token {
				delete(state.workers, r.workerID)
			}
		case relayLifecycleLegacy:
			worker, exists := state.legacy[r.token]
			if exists && worker.token == r.token {
				delete(state.legacy, r.token)
				state.legacyOrder = removeLegacyToken(state.legacyOrder, r.token)
			}
		}
	})
}

func (r *relayLifecycleRegistry) Stats() relayLifecycleStats {
	if r == nil {
		return relayLifecycleStats{}
	}
	return relayLifecycleStats{
		V2Replaced:    r.v2Replaced.Load(),
		V2StaleDenied: r.v2StaleDenied.Load(),
		LegacyEvicted: r.legacyEvicted.Load(),
	}
}
