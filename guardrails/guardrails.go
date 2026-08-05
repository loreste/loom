// Package guardrails enforces hard safety constraints before execution.
// Any failed guardrail is a deny. Errors are deny (fail-closed).
package guardrails

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Result of a single guardrail check.
type Result struct {
	Name    string
	OK      bool
	Message string
}

// Guardrail is one enforcement check.
type Guardrail interface {
	Name() string
	Check(ctx context.Context, id core.Identity, op *core.Operation, req *core.Request) Result
}

// Chain runs all guardrails; first failure wins (still records name).
type Chain struct {
	mu    sync.RWMutex
	items []Guardrail
}

// NewChain returns an empty chain. Empty chain allows (no constraints configured).
// Adversarial note: production should always register Schema + Secret + Production at minimum.
func NewChain(gs ...Guardrail) *Chain {
	c := &Chain{}
	for _, g := range gs {
		if g != nil {
			c.items = append(c.items, g)
		}
	}
	return c
}

// Add appends a guardrail.
func (c *Chain) Add(g Guardrail) {
	if c == nil || g == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, g)
}

// Len reports the number of configured guardrails.
func (c *Chain) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Has reports whether a named guardrail is configured.
func (c *Chain) Has(name string) bool {
	if c == nil || name == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, item := range c.items {
		if item != nil && item.Name() == name {
			return true
		}
	}
	return false
}

// ValidateOperation enforces category-specific safety controls at the
// operation boundary. An empty custom chain cannot accidentally make money or
// administrative effects executable.
func (c *Chain) ValidateOperation(op *core.Operation) error {
	if c == nil || op == nil {
		return fmt.Errorf("guardrails: chain or operation not configured")
	}
	if op.HasEffect(core.EffectMoney) && !c.Has("financial") {
		return fmt.Errorf("guardrails: money operation requires financial guardrail")
	}
	if (op.HasEffect(core.EffectDelete) || op.HasEffect(core.EffectAdmin)) && !c.Has("production") {
		return fmt.Errorf("guardrails: delete/admin operation requires production guardrail")
	}
	return nil
}

// Check runs all guardrails. Fail-closed on panic recovery as deny.
func (c *Chain) Check(ctx context.Context, id core.Identity, op *core.Operation, req *core.Request) Result {
	if c == nil {
		return Result{Name: "chain", OK: false, Message: "guardrail chain not configured"}
	}
	c.mu.RLock()
	items := append([]Guardrail(nil), c.items...)
	c.mu.RUnlock()

	for _, g := range items {
		if err := ctx.Err(); err != nil {
			return Result{Name: g.Name(), OK: false, Message: err.Error()}
		}
		res := safeCheck(g, ctx, id, op, req)
		if !res.OK {
			return res
		}
	}
	return Result{Name: "chain", OK: true, Message: "all guardrails passed"}
}

func safeCheck(g Guardrail, ctx context.Context, id core.Identity, op *core.Operation, req *core.Request) (res Result) {
	defer func() {
		if rec := recover(); rec != nil {
			res = Result{Name: g.Name(), OK: false, Message: fmt.Sprintf("guardrail panic: %v", rec)}
		}
	}()
	return g.Check(ctx, id, op, req)
}

// --- Schema validation (structural, minimal JSON Schema subset) ---

// SchemaGuard validates input against op.InputSchema when present.
// Unsupported schema keywords fail closed if schema is non-empty and invalid.
type SchemaGuard struct{}

func (SchemaGuard) Name() string { return "schema" }

func (SchemaGuard) Check(_ context.Context, _ core.Identity, op *core.Operation, req *core.Request) Result {
	if op == nil || len(op.InputSchema) == 0 {
		// No schema → structural pass only; still reject non-object nil input as empty map ok.
		if req.Input == nil {
			return Result{Name: "schema", OK: true, Message: "nil input coerced"}
		}
		return Result{Name: "schema", OK: true, Message: "no schema"}
	}
	var schema map[string]any
	if err := json.Unmarshal(op.InputSchema, &schema); err != nil {
		return Result{Name: "schema", OK: false, Message: "invalid input schema document"}
	}
	input := req.Input
	if input == nil {
		input = map[string]any{}
	}
	if err := ValidateSchema(op.InputSchema, input); err != nil {
		return Result{Name: "schema", OK: false, Message: err.Error()}
	}
	return Result{Name: "schema", OK: true, Message: "schema valid"}
}

func validateObject(schema map[string]any, input map[string]any) error {
	typ, _ := schema["type"].(string)
	if typ != "" && typ != "object" {
		return fmt.Errorf("root type must be object")
	}
	required, _ := schema["required"].([]any)
	for _, r := range required {
		name, ok := r.(string)
		if !ok {
			return fmt.Errorf("invalid required entry")
		}
		if _, exists := input[name]; !exists {
			return fmt.Errorf("missing required field %q", name)
		}
	}
	props, _ := schema["properties"].(map[string]any)
	additional, hasAdditional := schema["additionalProperties"]
	if hasAdditional {
		if allow, ok := additional.(bool); ok && !allow {
			for k := range input {
				if props != nil {
					if _, ok := props[k]; !ok {
						return fmt.Errorf("additional property %q not allowed", k)
					}
				} else {
					return fmt.Errorf("additional property %q not allowed", k)
				}
			}
		}
	}
	if props != nil {
		for k, v := range input {
			ps, ok := props[k].(map[string]any)
			if !ok {
				continue
			}
			if err := validateValue(ps, v); err != nil {
				return fmt.Errorf("field %q: %w", k, err)
			}
		}
	}
	return nil
}

// schemaPatternCache memoizes compiled schema patterns (hot path); compile errors deny.
var schemaPatternCache sync.Map // pattern string → *regexp.Regexp

const maxSchemaPatternLen = 256

func compileSchemaPattern(pat string) (*regexp.Regexp, error) {
	if len(pat) > maxSchemaPatternLen {
		return nil, fmt.Errorf("pattern too long")
	}
	if re, ok := schemaPatternCache.Load(pat); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	actual, _ := schemaPatternCache.LoadOrStore(pat, re)
	return actual.(*regexp.Regexp), nil
}

func validateValue(schema map[string]any, v any) error {
	typ, _ := schema["type"].(string)
	switch typ {
	case "string":
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("expected string")
		}
		if max, ok := num(schema["maxLength"]); ok && float64(len(s)) > max {
			return fmt.Errorf("string too long")
		}
		if min, ok := num(schema["minLength"]); ok && float64(len(s)) < min {
			return fmt.Errorf("string too short")
		}
		if pat, ok := schema["pattern"].(string); ok && pat != "" {
			re, err := compileSchemaPattern(pat)
			if err != nil {
				return fmt.Errorf("invalid pattern in schema")
			}
			if !re.MatchString(s) {
				return fmt.Errorf("pattern mismatch")
			}
		}
	case "number", "integer":
		f, ok := num(v)
		if !ok {
			return fmt.Errorf("expected number")
		}
		if typ == "integer" && f != float64(int64(f)) {
			return fmt.Errorf("expected integer")
		}
		if max, ok := num(schema["maximum"]); ok && f > max {
			return fmt.Errorf("above maximum")
		}
		if min, ok := num(schema["minimum"]); ok && f < min {
			return fmt.Errorf("below minimum")
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("expected boolean")
		}
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		return validateObject(schema, m)
	case "array":
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("expected array")
		}
		if max, ok := num(schema["maxItems"]); ok && float64(len(arr)) > max {
			return fmt.Errorf("too many items")
		}
	case "":
		// no type constraint
	default:
		return fmt.Errorf("unsupported schema type %q", typ)
	}
	return nil
}

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// --- Financial limits ---

// FinancialGuard blocks money-effect operations exceeding amount limits.
// Fail-closed: with no positive limit configured (and Unlimited false), money
// operations are denied. Set Unlimited explicitly to opt out of ceilings.
type FinancialGuard struct {
	// MaxAmount absolute ceiling for input field "amount" (or AmountField).
	MaxAmount   core.Money
	AmountField string
	// Unlimited explicitly disables ceilings (zero-value guard is deny, not unlimited).
	Unlimited bool
	// MaxByPrincipal optional per-principal ceilings.
	MaxByPrincipal map[core.PrincipalID]core.Money
	// MaxByCurrency optionally supplies a separate exact ceiling per currency.
	// It is useful when an operation explicitly allows more than one currency.
	MaxByCurrency map[string]core.Money
	mu            sync.RWMutex
}

func (g *FinancialGuard) Name() string { return "financial" }

func (g *FinancialGuard) Check(_ context.Context, id core.Identity, op *core.Operation, req *core.Request) Result {
	if op == nil || !op.HasEffect(core.EffectMoney) {
		return Result{Name: "financial", OK: true, Message: "not a money operation"}
	}
	field := g.AmountField
	if field == "" {
		field = "amount"
	}
	raw, ok := req.Input[field]
	if !ok {
		return Result{Name: "financial", OK: false, Message: "money operation missing amount"}
	}
	currency, _ := req.Input["currency"].(string)
	if currency == "" {
		currency = g.MaxAmount.Currency
	}
	if currency == "" {
		currency = "XXX"
	}
	amount, err := core.ParseMoney(raw, currency)
	if err != nil {
		return Result{Name: "financial", OK: false, Message: "invalid amount"}
	}
	if !core.CurrencyAllowed(amount.Currency, op.AllowedCurrencies) {
		return Result{Name: "financial", OK: false, Message: "currency is not allowed for this operation"}
	}
	max := g.MaxAmount
	g.mu.RLock()
	if g.MaxByCurrency != nil {
		if m, exists := g.MaxByCurrency[amount.CurrencyCode()]; exists {
			max = m
		}
	}
	if g.MaxByPrincipal != nil {
		if m, exists := g.MaxByPrincipal[id.ID]; exists {
			max = m
		}
	}
	g.mu.RUnlock()
	if !max.Valid() && !g.Unlimited {
		return Result{Name: "financial", OK: false, Message: "financial guard has no limit configured (deny)"}
	}
	if !g.Unlimited {
		cmp, err := amount.Compare(max)
		if err != nil {
			return Result{Name: "financial", OK: false, Message: "amount currency does not match limit"}
		}
		if cmp > 0 {
			return Result{Name: "financial", OK: false, Message: "amount exceeds configured limit"}
		}
	}
	return Result{Name: "financial", OK: true, Message: "within limit"}
}

// --- Network restrictions ---

// NetworkGuard rejects private/link-local/metadata targets when input contains URLs/hosts.
type NetworkGuard struct {
	// HostFields lists input keys that must be public hosts if present.
	HostFields []string
	// AllowPrivate when true weakens the guard (default false).
	AllowPrivate bool
	// SkipDNS when true only checks literal IPs/hostnames (no resolution).
	// Default false: hostnames are resolved and any private/link-local answer is denied.
	SkipDNS bool
	// Resolver optional; nil uses net.DefaultResolver.
	Resolver interface {
		LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	}
}

func (g NetworkGuard) Name() string { return "network" }

func (g NetworkGuard) Check(ctx context.Context, _ core.Identity, _ *core.Operation, req *core.Request) Result {
	fields := g.HostFields
	if len(fields) == 0 {
		fields = []string{"host", "url", "endpoint", "target"}
	}
	// Also scan one level of nested maps for the same field names (webhook configs).
	candidates := collectHostCandidates(req.Input, fields)
	for _, s := range candidates {
		host := extractHost(s)
		if host == "" {
			return Result{Name: "network", OK: false, Message: "empty host"}
		}
		if !g.AllowPrivate && g.isBlockedHost(ctx, host) {
			return Result{Name: "network", OK: false, Message: "host blocked by network guardrail: " + host}
		}
	}
	return Result{Name: "network", OK: true, Message: "network ok"}
}

func collectHostCandidates(input map[string]any, fields []string) []string {
	if input == nil {
		return nil
	}
	want := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		want[strings.ToLower(f)] = struct{}{}
	}
	var out []string
	var walk func(map[string]any, int)
	walk = func(m map[string]any, depth int) {
		if m == nil || depth > 3 {
			return
		}
		for k, v := range m {
			if _, ok := want[strings.ToLower(k)]; ok {
				if s, ok := v.(string); ok {
					out = append(out, s)
				}
			}
			if nested, ok := v.(map[string]any); ok {
				walk(nested, depth+1)
			}
		}
	}
	walk(input, 0)
	return out
}

func extractHost(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			// Claims to be a URL but the host is unusable: fail closed.
			return ""
		}
		// Hostname strips userinfo, brackets, and port.
		return u.Hostname()
	}
	// Strip userinfo from bare authority forms (user@host).
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return strings.Trim(s, "[]")
	}
	return host
}

func (g NetworkGuard) isBlockedHost(ctx context.Context, host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "" || h == "localhost" || h == "metadata.google.internal" ||
		h == "metadata" || strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".internal") {
		return true
	}
	ip, ok := parseHostIP(h)
	if ok {
		return isBlockedIP(ip)
	}
	if g.SkipDNS {
		return false
	}
	// Resolve hostnames and deny if any answer is non-public (SSRF rebinding).
	// DNS errors fail closed (deny).
	r := g.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := r.LookupIPAddr(lookupCtx, h)
	if err != nil || len(addrs) == 0 {
		return true // fail closed
	}
	for _, a := range addrs {
		addr, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return true
		}
		if isBlockedIP(addr) {
			return true
		}
	}
	return false
}

func isBlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// Cloud metadata range 169.254.0.0/16 is link-local (covered). CGNAT 100.64/10 optional.
	return false
}

// parseHostIP parses canonical IPs plus non-dotted IPv4 forms (decimal,
// octal, hex, shortened) that browsers accept and naive dotted-quad parsers miss.
func parseHostIP(h string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(h); err == nil {
		return a, true
	}
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	nums := make([]uint64, 0, len(parts))
	for _, p := range parts {
		if p == "" || len(p) > 11 {
			return netip.Addr{}, false
		}
		// base 0 accepts decimal, 0x hex, and leading-0 octal; rejects signs/letters.
		v, err := strconv.ParseUint(p, 0, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		nums = append(nums, v)
	}
	// inet_aton semantics: the final component spans the remaining bytes.
	var addr uint32
	for i := 0; i < len(nums)-1; i++ {
		if nums[i] > 255 {
			return netip.Addr{}, false
		}
		addr |= uint32(nums[i]) << uint(24-8*i)
	}
	last := nums[len(nums)-1]
	remBytes := 4 - (len(nums) - 1)
	if remBytes >= 4 {
		// single component is the full 32-bit address; ParseUint already capped it
		addr |= uint32(last)
	} else {
		if last >= uint64(1)<<uint(8*remBytes) {
			return netip.Addr{}, false
		}
		addr |= uint32(last)
	}
	return netip.AddrFrom4([4]byte{byte(addr >> 24), byte(addr >> 16), byte(addr >> 8), byte(addr)}), true
}

// --- Filesystem sandbox ---

// FilesystemGuard blocks path traversal and absolute paths outside prefixes.
type FilesystemGuard struct {
	// PathFields input keys to check.
	PathFields []string
	// AllowedPrefixes; empty means deny all path-like inputs when present.
	AllowedPrefixes []string
}

func (g FilesystemGuard) Name() string { return "filesystem" }

func (g FilesystemGuard) Check(_ context.Context, _ core.Identity, _ *core.Operation, req *core.Request) Result {
	fields := g.PathFields
	if len(fields) == 0 {
		fields = []string{"path", "file", "filepath", "directory"}
	}
	for _, f := range fields {
		raw, ok := req.Input[f]
		if !ok {
			continue
		}
		p, ok := raw.(string)
		if !ok {
			return Result{Name: "filesystem", OK: false, Message: f + " must be string"}
		}
		if strings.Contains(p, "..") {
			return Result{Name: "filesystem", OK: false, Message: "path traversal blocked"}
		}
		if strings.Contains(p, "\x00") {
			return Result{Name: "filesystem", OK: false, Message: "null byte in path"}
		}
		if len(g.AllowedPrefixes) == 0 {
			return Result{Name: "filesystem", OK: false, Message: "no filesystem prefixes allowed"}
		}
		allowed := false
		for _, pref := range g.AllowedPrefixes {
			if pref == "" {
				continue
			}
			// Match only at a path boundary: "/data" must not allow "/data2/secret".
			clean := strings.TrimSuffix(pref, "/")
			if p == clean || strings.HasPrefix(p, clean+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return Result{Name: "filesystem", OK: false, Message: "path outside sandbox"}
		}
	}
	return Result{Name: "filesystem", OK: true, Message: "filesystem ok"}
}

// --- Production protections ---

// ProductionGuard blocks destructive effects in production boundaries.
type ProductionGuard struct {
	// ProductionBoundaries lists boundary IDs considered production.
	ProductionBoundaries map[core.BoundaryID]struct{}
	// BlockEffects in production (default: delete, exec, admin).
	BlockEffects []core.Effect
}

func (g *ProductionGuard) Name() string { return "production" }

func (g *ProductionGuard) Check(_ context.Context, _ core.Identity, op *core.Operation, req *core.Request) Result {
	if g == nil || op == nil {
		return Result{Name: "production", OK: false, Message: "production guard misconfigured"}
	}
	if _, prod := g.ProductionBoundaries[req.Boundary]; !prod {
		return Result{Name: "production", OK: true, Message: "non-production"}
	}
	blocked := g.BlockEffects
	if len(blocked) == 0 {
		blocked = []core.Effect{core.EffectDelete, core.EffectExec, core.EffectAdmin}
	}
	for _, e := range blocked {
		if op.HasEffect(e) {
			return Result{Name: "production", OK: false, Message: fmt.Sprintf("effect %s blocked in production", e)}
		}
	}
	return Result{Name: "production", OK: true, Message: "production ok"}
}

// --- AI recursion / prompt injection containment ---

// AIGuard limits AI-effect operations and strips injection markers from inputs.
type AIGuard struct {
	MaxDepthField string // input field for recursion depth
	MaxDepth      int
}

func (g AIGuard) Name() string { return "ai" }

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions`),
	regexp.MustCompile(`(?i)system\s*:\s*`),
	regexp.MustCompile(`(?i)<\|?(system|endofprompt)\|?>`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+DAN`),
}

func (g AIGuard) Check(_ context.Context, _ core.Identity, op *core.Operation, req *core.Request) Result {
	if op == nil || !op.HasEffect(core.EffectAI) {
		return Result{Name: "ai", OK: true, Message: "not ai op"}
	}
	maxDepth := g.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	field := g.MaxDepthField
	if field == "" {
		field = "depth"
	}
	if raw, ok := req.Input[field]; ok {
		d, ok := num(raw)
		if !ok || d < 0 {
			return Result{Name: "ai", OK: false, Message: "invalid depth"}
		}
		if int(d) > maxDepth {
			return Result{Name: "ai", OK: false, Message: "AI recursion depth exceeded"}
		}
	}
	// Scan string fields for injection
	for k, v := range req.Input {
		s, ok := v.(string)
		if !ok {
			continue
		}
		for _, re := range injectionPatterns {
			if re.MatchString(s) {
				return Result{Name: "ai", OK: false, Message: "prompt injection pattern in " + k}
			}
		}
	}
	return Result{Name: "ai", OK: true, Message: "ai guard ok"}
}

// --- Secret redaction on input echo (pre-exec) ---

// SecretGuard rejects inputs that appear to contain raw secrets in disallowed fields,
// and is used by output filtering for redaction patterns.
type SecretGuard struct {
	// ForbiddenInputFields reject if present with non-empty values (e.g. raw private keys).
	ForbiddenInputFields []string
}

func (g SecretGuard) Name() string { return "secret" }

var secretValuePattern = regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,}|password\s*[=:]\s*\S+)`)

func (g SecretGuard) Check(_ context.Context, _ core.Identity, _ *core.Operation, req *core.Request) Result {
	forbidden := g.ForbiddenInputFields
	if len(forbidden) == 0 {
		forbidden = []string{"private_key", "password", "secret", "api_key_raw"}
	}
	for _, f := range forbidden {
		if v, ok := req.Input[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				return Result{Name: "secret", OK: false, Message: "forbidden secret field: " + f}
			}
		}
	}
	for k, v := range req.Input {
		if containsSecret(v) {
			return Result{Name: "secret", OK: false, Message: "secret-like value in field " + k}
		}
	}
	return Result{Name: "secret", OK: true, Message: "no secrets detected"}
}

// containsSecret reports whether v (or any nested string in slices/maps) matches a secret pattern.
func containsSecret(v any) bool {
	switch t := v.(type) {
	case string:
		return secretValuePattern.MatchString(t)
	case []any:
		for _, e := range t {
			if containsSecret(e) {
				return true
			}
		}
	case []string:
		for _, e := range t {
			if secretValuePattern.MatchString(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range t {
			if containsSecret(e) {
				return true
			}
		}
	}
	return false
}

func hasNonEmptyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(t) != ""
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	default:
		return true
	}
}

func isSensitiveScalar(v any) bool {
	switch v.(type) {
	case map[string]any, map[string]string, []any, []string:
		return false
	default:
		return hasNonEmptyValue(v)
	}
}

// sensitiveFieldName is intentionally conservative. It is used for both
// input rejection and audit/output redaction, so a false positive is safer
// than persisting a credential under an application-specific field name.
func sensitiveFieldName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, fragment := range []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"authorization", "cookie", "private_key", "client_secret",
		"access_key", "refresh_token", "credential", "dsn",
		"connection_string",
	} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

// ScrubString redacts secret-like substrings from s (used for audit messages).
func ScrubString(s string) string {
	if s == "" {
		return s
	}
	return secretValuePattern.ReplaceAllString(s, "[REDACTED]")
}

func redactValue(v any) any {
	switch t := v.(type) {
	case string:
		if secretValuePattern.MatchString(t) {
			return "[REDACTED]"
		}
		return t
	case map[string]any:
		return RedactSecrets(t)
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, value := range t {
			if sensitiveFieldName(k) && strings.TrimSpace(value) != "" {
				out[k] = "[REDACTED]"
			} else if secretValuePattern.MatchString(value) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = value
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactValue(e)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, e := range t {
			if secretValuePattern.MatchString(e) {
				out[i] = "[REDACTED]"
			} else {
				out[i] = e
			}
		}
		return out
	default:
		return v
	}
}

// RedactSecrets returns a deep copy of m with secret-like strings replaced.
func RedactSecrets(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sensitiveFieldName(k) && isSensitiveScalar(v) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = redactValue(v)
		}
	}
	return out
}

// RedactSecretPatterns preserves explicitly generated values such as an
// approval token while still removing known secret-shaped strings. Audit
// logging uses RedactSecrets, which additionally redacts sensitive field
// names; response filtering uses this less destructive variant.
func RedactSecretPatterns(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = redactPatternValue(v)
	}
	return out
}

func redactPatternValue(v any) any {
	switch t := v.(type) {
	case string:
		if secretValuePattern.MatchString(t) {
			return "[REDACTED]"
		}
		return t
	case map[string]any:
		return RedactSecretPatterns(t)
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, value := range t {
			if secretValuePattern.MatchString(value) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = value
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = redactPatternValue(item)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, item := range t {
			if secretValuePattern.MatchString(item) {
				out[i] = "[REDACTED]"
			} else {
				out[i] = item
			}
		}
		return out
	default:
		return v
	}
}

// DefaultChain returns a production-leaning adversarial default set.
func DefaultChain() *Chain {
	return NewChain(
		SchemaGuard{},
		&FinancialGuard{MaxAmount: core.Money{Units: 10_000, Currency: "USD"}},
		NetworkGuard{},
		FilesystemGuard{AllowedPrefixes: []string{"/data/", "/tmp/loom/"}},
		&ProductionGuard{ProductionBoundaries: map[core.BoundaryID]struct{}{"prod": {}}},
		AIGuard{MaxDepth: 3},
		SecretGuard{},
	)
}
