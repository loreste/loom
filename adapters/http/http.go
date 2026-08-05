// Package http adapts HTTP to Loom. It never bypasses the runtime.
//
// Use NewServer for the full edge (health, limits, security headers).
// Handler remains as a minimal POST adapter for embedding.
package http
