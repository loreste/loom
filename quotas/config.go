package quotas

import (
	"fmt"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Config holds quota windows shared by memory and Redis limiters.
type Config struct {
	mu              sync.RWMutex
	limits          map[string]Window
	DefaultLimit    int64
	DefaultInterval time.Duration
}

// NewConfig returns an empty limit configuration.
func NewConfig() *Config {
	return &Config{
		limits:          make(map[string]Window),
		DefaultInterval: time.Minute,
	}
}

// SetLimit configures principal|boundary|op. op may be "*".
func (c *Config) SetLimit(principal core.PrincipalID, boundary core.BoundaryID, op string, limit int64, interval time.Duration) error {
	if c == nil {
		return fmt.Errorf("%w: nil config", core.ErrInvalidArgument)
	}
	if limit <= 0 || interval <= 0 {
		return fmt.Errorf("%w: limit and interval must be positive", core.ErrInvalidArgument)
	}
	key := LimitKey(principal, boundary, op)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limits == nil {
		c.limits = make(map[string]Window)
	}
	c.limits[key] = Window{Limit: limit, Interval: interval}
	return nil
}

// Resolve finds the most specific window for the call.
// ok=false means no limit (unlimited) when DefaultLimit is 0.
func (c *Config) Resolve(id core.PrincipalID, boundary core.BoundaryID, op string) (Window, bool) {
	if c == nil {
		return Window{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	candidates := []string{
		LimitKey(id, boundary, op),
		LimitKey(id, boundary, "*"),
		LimitKey("*", boundary, op),
		LimitKey("*", "*", "*"),
	}
	for _, k := range candidates {
		if w, ok := c.limits[k]; ok {
			return w, true
		}
	}
	if c.DefaultLimit > 0 {
		iv := c.DefaultInterval
		if iv <= 0 {
			iv = time.Minute
		}
		return Window{Limit: c.DefaultLimit, Interval: iv}, true
	}
	return Window{}, false
}

// LimitKey builds the config lookup key.
func LimitKey(p core.PrincipalID, b core.BoundaryID, op string) string {
	return string(p) + "|" + string(b) + "|" + op
}

// CounterKey builds a time-bucketed counter key for distributed limiters.
func CounterKey(prefix string, p core.PrincipalID, b core.BoundaryID, op string, bucket int64) string {
	if prefix == "" {
		prefix = "loom:quota"
	}
	return fmt.Sprintf("%s:%s|%s|%s:%d", prefix, p, b, op, bucket)
}
