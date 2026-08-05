package core

import (
	"crypto/rand"
	"encoding/hex"
)

// NewTraceID generates a 16-byte random hex trace id.
// Failures return a fixed sentinel rather than empty (empty breaks audit correlation).
func NewTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}
