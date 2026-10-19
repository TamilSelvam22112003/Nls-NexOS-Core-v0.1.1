package directory

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrDuplicateEndpoint = errors.New("endpoint already registered to another router")
	ErrStaleGeneration   = errors.New("RDR generation must increase")
	ErrRouterNotFound    = errors.New("router not found")
	ErrRouterInactive    = errors.New("router is not active")
)

// Registry stores only verified, current RDRs. Register is atomic with respect
// to router-ID, endpoint, and generation checks.
type Registry struct {
	mu      sync.RWMutex
	records map[[16]byte][]byte
}

func NewRegistry() *Registry {
	return &Registry{records: make(map[[16]byte][]byte)}
}

func (r *Registry) Register(record []byte, nowUnixMS uint64) error {
	fields, err := VerifyRDR(record, nowUnixMS)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.records[fields.RouterID]; ok {
		oldFields, verifyErr := VerifyRDR(old, 0)
		if verifyErr != nil {
			return fmt.Errorf("stored RDR invalid: %w", verifyErr)
		}
		if fields.Generation <= oldFields.Generation {
			return ErrStaleGeneration
		}
	}
	for id, old := range r.records {
		if id == fields.RouterID {
			continue
		}
		oldFields, verifyErr := VerifyRDR(old, 0)
		if verifyErr != nil {
			return fmt.Errorf("stored RDR invalid: %w", verifyErr)
		}
		if bytes.Equal(oldFields.EndpointIPv6[:], fields.EndpointIPv6[:]) &&
			oldFields.EndpointPort == fields.EndpointPort {
			return ErrDuplicateEndpoint
		}
	}
	r.records[fields.RouterID] = append([]byte(nil), record...)
	return nil
}

// Lookup returns a defensive copy of an ACTIVE, unexpired signed record.
func (r *Registry) Lookup(routerID [16]byte, nowUnixMS uint64) ([]byte, error) {
	r.mu.RLock()
	record, ok := r.records[routerID]
	if ok {
		record = append([]byte(nil), record...)
	}
	r.mu.RUnlock()
	if !ok {
		return nil, ErrRouterNotFound
	}
	fields, err := VerifyRDR(record, nowUnixMS)
	if err != nil {
		return nil, err
	}
	if fields.Status != StatusActive {
		return nil, ErrRouterInactive
	}
	return record, nil
}
