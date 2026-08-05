package db

import (
	"fmt"
	"strings"
)

// Dialect identifies placeholder style and minor SQL quirks.
type Dialect int

const (
	// DialectUnknown fails closed for rebind (returns error).
	DialectUnknown Dialect = iota
	// DialectSQLite uses ? placeholders.
	DialectSQLite
	// DialectPostgres uses $1, $2, ... placeholders.
	DialectPostgres
)

func (d Dialect) String() string {
	switch d {
	case DialectSQLite:
		return "sqlite"
	case DialectPostgres:
		return "postgres"
	default:
		return "unknown"
	}
}

// DetectDialect maps a database/sql driver name to a Dialect.
func DetectDialect(driver string) Dialect {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "sqlite", "sqlite3":
		return DialectSQLite
	case "pgx", "postgres", "postgresql", "pq":
		return DialectPostgres
	default:
		return DialectUnknown
	}
}

// Rebind converts ? placeholders to the dialect form.
// Already-bound $n forms are left as-is when dialect is Postgres.
// Fail-closed: unknown dialect returns error.
func Rebind(dialect Dialect, query string) (string, error) {
	switch dialect {
	case DialectSQLite:
		return query, nil
	case DialectPostgres:
		return rebindPostgres(query), nil
	default:
		return "", fmt.Errorf("db: unknown dialect for rebind")
	}
}

func rebindPostgres(query string) string {
	// If already uses $n and no ?, leave alone.
	if !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inSingle := false
	inDouble := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			b.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			b.WriteByte(c)
		case c == '?' && !inSingle && !inDouble:
			n++
			fmt.Fprintf(&b, "$%d", n)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Dialect returns the pool dialect (from Options or detected driver).
func (p *Pool) Dialect() Dialect {
	if p == nil {
		return DialectUnknown
	}
	if p.opts.Dialect != DialectUnknown {
		return p.opts.Dialect
	}
	return DetectDialect(p.opts.DriverName)
}

// Dialect on executor.
func (e *Executor) Dialect() Dialect {
	if e == nil || e.pool == nil {
		return DialectUnknown
	}
	return e.pool.Dialect()
}

// Q rebinds SQL for this executor's dialect.
func (e *Executor) Q(sqlText string) (string, error) {
	return Rebind(e.Dialect(), sqlText)
}
