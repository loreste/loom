// Package hello provides a thin wrapper around the platform stack for demos.
package hello

import (
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/runtime"
)

// Stack returns the platform runtime for backwards compatibility with early demos.
func Stack() (*runtime.TestStack, error) {
	// Prefer full platform via Platform(); kept for older tests that expect TestStack.
	return runtime.NewTestStack()
}

// Platform returns the Phase-2 bootstrap stack.
func Platform() (*bootstrap.Platform, error) {
	return bootstrap.NewPlatform(bootstrap.Config{})
}
