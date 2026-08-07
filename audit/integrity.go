package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// HashEvent returns the canonical SHA-256 hash used by the audit hash chain.
// EventHash is excluded from the input so the value can be independently
// recomputed from a stored event.
func HashEvent(event Event) (string, error) {
	event.EventHash = ""
	payload, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("audit: hash event: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// HashChainSink adds a previous-hash link and event hash before forwarding an
// event. The previous hash should be loaded from a trusted checkpoint when a
// process restarts; it must not be guessed from untrusted log input.
type HashChainSink struct {
	Sink Sink

	mu       sync.Mutex
	previous string
}

// NewHashChainSink wraps a sink. previousHash is empty only for the first
// event in a new chain or when the caller intentionally starts a new stream.
func NewHashChainSink(sink Sink, previousHash string) *HashChainSink {
	return &HashChainSink{Sink: sink, previous: previousHash}
}

// Durable forwards the underlying sink's durability declaration.
func (s *HashChainSink) Durable() bool {
	if s == nil || s.Sink == nil {
		return false
	}
	durable, ok := s.Sink.(interface{ Durable() bool })
	return ok && durable.Durable()
}

// PreviousHash returns the last successfully persisted event hash.
func (s *HashChainSink) PreviousHash() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.previous
}

// Write hashes and persists one event atomically with respect to other
// writers. The chain advances only after the wrapped sink accepts the event.
func (s *HashChainSink) Write(ctx context.Context, event Event) error {
	if s == nil || s.Sink == nil {
		return fmt.Errorf("audit: hash-chain sink is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event.PrevEventHash = s.previous
	hash, err := HashEvent(event)
	if err != nil {
		return err
	}
	event.EventHash = hash
	if err := s.Sink.Write(ctx, event); err != nil {
		return err
	}
	s.previous = hash
	return nil
}

// VerifyChain checks links and hashes for a contiguous event sequence.
// initialHash is the trusted checkpoint hash immediately before events[0].
func VerifyChain(events []Event, initialHash string) error {
	previous := initialHash
	for index, event := range events {
		if event.PrevEventHash != previous {
			return fmt.Errorf("audit: event %d previous hash mismatch", index)
		}
		computed, err := HashEvent(event)
		if err != nil {
			return err
		}
		if event.EventHash == "" || !hmac.Equal([]byte(event.EventHash), []byte(computed)) {
			return fmt.Errorf("audit: event %d hash mismatch", index)
		}
		previous = event.EventHash
	}
	return nil
}

// StreamExporter returns one contiguous, verified segment of a durable audit
// stream. Implementations must verify the chain against trustedPreviousHash
// and fail closed on a gap, a reordering, or a stream mismatch, so a caller
// cannot be handed a segment that only looks intact.
type StreamExporter interface {
	ExportStream(ctx context.Context, streamID string, fromSequence, toSequence int64, trustedPreviousHash string) ([]Event, error)
}

// Checkpoint is a signed, portable assertion about the end of an audit
// sequence. Store checkpoints separately from the event stream, preferably in
// an immutable or WORM-backed retention system.
type Checkpoint struct {
	Version       int       `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	EventCount    int       `json:"event_count"`
	LastEventHash string    `json:"last_event_hash,omitempty"`
	Signature     string    `json:"signature,omitempty"`
}

// CheckpointSigner signs and verifies the canonical checkpoint payload. A KMS
// or HSM-backed implementation should be used for regulated deployments.
type CheckpointSigner interface {
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) error
}

// CreateCheckpoint verifies a complete chain and signs its terminal hash.
func CreateCheckpoint(events []Event, signer CheckpointSigner) (Checkpoint, error) {
	if err := VerifyChain(events, ""); err != nil {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		EventCount: len(events),
	}
	if len(events) > 0 {
		checkpoint.LastEventHash = events[len(events)-1].EventHash
	}
	if signer == nil {
		return checkpoint, nil
	}
	signature, err := signer.Sign(checkpointPayload(checkpoint))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: sign checkpoint: %w", err)
	}
	checkpoint.Signature = base64.RawStdEncoding.EncodeToString(signature)
	return checkpoint, nil
}

// VerifyCheckpoint verifies both the event sequence and its signed terminal
// hash. It rejects a missing signature when a signer is supplied.
func VerifyCheckpoint(events []Event, checkpoint Checkpoint, signer CheckpointSigner) error {
	if checkpoint.Version != 1 {
		return fmt.Errorf("audit: unsupported checkpoint version %d", checkpoint.Version)
	}
	if err := VerifyChain(events, ""); err != nil {
		return err
	}
	if checkpoint.EventCount != len(events) {
		return fmt.Errorf("audit: checkpoint event count mismatch")
	}
	lastHash := ""
	if len(events) > 0 {
		lastHash = events[len(events)-1].EventHash
	}
	if checkpoint.LastEventHash != lastHash {
		return fmt.Errorf("audit: checkpoint terminal hash mismatch")
	}
	if signer == nil {
		if checkpoint.Signature != "" {
			return fmt.Errorf("audit: checkpoint signature cannot be verified")
		}
		return nil
	}
	if checkpoint.Signature == "" {
		return fmt.Errorf("audit: checkpoint signature is required")
	}
	signature, err := base64.RawStdEncoding.DecodeString(checkpoint.Signature)
	if err != nil {
		return fmt.Errorf("audit: decode checkpoint signature: %w", err)
	}
	if err := signer.Verify(checkpointPayload(checkpoint), signature); err != nil {
		return fmt.Errorf("audit: verify checkpoint: %w", err)
	}
	return nil
}

func checkpointPayload(checkpoint Checkpoint) []byte {
	payload, _ := json.Marshal(struct {
		Version       int       `json:"version"`
		CreatedAt     time.Time `json:"created_at"`
		EventCount    int       `json:"event_count"`
		LastEventHash string    `json:"last_event_hash,omitempty"`
	}{
		Version:       checkpoint.Version,
		CreatedAt:     checkpoint.CreatedAt.UTC(),
		EventCount:    checkpoint.EventCount,
		LastEventHash: checkpoint.LastEventHash,
	})
	return payload
}

// HMACCheckpointSigner is a small helper for deployments that manage a
// dedicated checkpoint key themselves. Prefer a KMS/HSM-backed signer when
// checkpoint authenticity must survive host compromise.
type HMACCheckpointSigner struct {
	key []byte
}

// NewHMACCheckpointSigner requires a non-trivial caller-provided key. Loom
// never supplies or persists a default signing key.
func NewHMACCheckpointSigner(key []byte) (*HMACCheckpointSigner, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("audit: checkpoint key must contain at least 32 bytes")
	}
	return &HMACCheckpointSigner{key: append([]byte(nil), key...)}, nil
}

func (s *HMACCheckpointSigner) Sign(payload []byte) ([]byte, error) {
	if s == nil || len(s.key) == 0 {
		return nil, fmt.Errorf("audit: checkpoint signer is not configured")
	}
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write(payload)
	return h.Sum(nil), nil
}

func (s *HMACCheckpointSigner) Verify(payload, signature []byte) error {
	expected, err := s.Sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, signature) {
		return fmt.Errorf("audit: invalid checkpoint signature")
	}
	return nil
}
