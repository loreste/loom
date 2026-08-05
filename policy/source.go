package policy

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Source loads a versioned policy document from a durable backend.
type Source interface {
	// Load returns the current document. ErrNotFound if none.
	Load(ctx context.Context) (*Document, error)
	// Publish stores a new document. Implementations must reject version <= current.
	Publish(ctx context.Context, doc *Document) error
}

// FileSource reads/writes a JSON policy file.
type FileSource struct {
	Path string
	mu   sync.Mutex
}

// NewFileSource creates a file-backed source.
func NewFileSource(path string) *FileSource {
	return &FileSource{Path: path}
}

// Load implements Source.
func (s *FileSource) Load(_ context.Context) (*Document, error) {
	if s == nil || s.Path == "" {
		return nil, fmt.Errorf("%w: path required", core.ErrInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.ErrNotFound
		}
		return nil, err
	}
	return ParseDocument(b)
}

// Publish implements Source (atomic write).
func (s *FileSource) Publish(_ context.Context, doc *Document) error {
	if s == nil || s.Path == "" {
		return fmt.Errorf("%w: path required", core.ErrInvalidArgument)
	}
	if doc == nil || doc.Version <= 0 {
		return fmt.Errorf("%w: document version must be > 0", core.ErrInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, err := os.ReadFile(s.Path); err == nil {
		cur, err := ParseDocument(b)
		if err == nil && doc.Version <= cur.Version {
			return fmt.Errorf("%w: policy version %d <= current %d", core.ErrAlreadyExists, doc.Version, cur.Version)
		}
	}
	doc.UpdatedAt = time.Now().UTC()
	if doc.ID == "" {
		doc.ID = "default"
	}
	raw, err := doc.Bytes()
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}
