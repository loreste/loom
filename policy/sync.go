package policy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Syncer periodically loads policy from Source and applies to MemoryEngine.
// Adversarial:
//   - Corrupt/parse errors keep previous rules (never wipe to empty on bad fetch)
//   - Only apply when remote Version > local applied version
//   - On apply failure, keep previous rules
type Syncer struct {
	Source   Source
	Engine   *MemoryEngine
	Interval time.Duration
	Logger   *log.Logger

	mu             sync.Mutex
	appliedVersion int64
	started        bool
	stop           chan struct{}
	done           chan struct{}
}

// NewSyncer constructs a syncer. Interval default 5s.
func NewSyncer(src Source, eng *MemoryEngine, interval time.Duration) *Syncer {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Syncer{
		Source:   src,
		Engine:   eng,
		Interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// AppliedVersion returns the last successfully applied version.
func (s *Syncer) AppliedVersion() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appliedVersion
}

// SyncOnce loads and applies if newer.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	if s == nil || s.Source == nil || s.Engine == nil {
		return fmt.Errorf("%w: syncer not configured", core.ErrInvalidArgument)
	}
	doc, err := s.Source.Load(ctx)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil // no remote policy yet — keep seeded rules
		}
		return err
	}
	// Serialize version-check + apply + version update so a concurrent stale
	// apply cannot overwrite a newer one. ReplaceRules takes the engine's own
	// lock, not s.mu, so there is no self-deadlock.
	s.mu.Lock()
	defer s.mu.Unlock()
	if doc.Version <= s.appliedVersion {
		return nil
	}
	if err := s.Engine.ReplaceRules(doc.Rules); err != nil {
		return fmt.Errorf("apply policy v%d: %w", doc.Version, err)
	}
	s.appliedVersion = doc.Version
	if s.Logger != nil {
		s.Logger.Printf("policy: applied version %d (%d rules)", doc.Version, len(doc.Rules))
	}
	return nil
}

// Start runs background sync until Stop. Call SyncOnce before Start if you need a hard fail on first load.
func (s *Syncer) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	go func() {
		defer close(s.done)
		t := time.NewTicker(s.Interval)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.SyncOnce(ctx); err != nil && s.Logger != nil {
					s.Logger.Printf("policy: sync: %v", err)
				}
			}
		}
	}()
}

// Stop ends background sync and waits. Safe if Start was never called.
func (s *Syncer) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	if started {
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
		}
	}
}
