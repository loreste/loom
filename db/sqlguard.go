package db

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// StatementClass is the safety class of a SQL statement.
type StatementClass string

const (
	ClassRead    StatementClass = "read"
	ClassWrite   StatementClass = "write"
	ClassDDL     StatementClass = "ddl"
	ClassAdmin   StatementClass = "admin"
	ClassUnknown StatementClass = "unknown"
)

var (
	// multiStatement rejects ; not in strings — fail closed: any ; is reject.
	reCommentLine  = regexp.MustCompile(`--`)
	reCommentBlock = regexp.MustCompile(`/\*|\*/`)
	// crude table extractors — identifiers may be "double"/'single'/`backtick`
	// quoted and optionally schema-qualified: users, public.users, public."users"
	qi       = `(?:"[^"]*"|'[^']*'|` + "`[^`]*`" + `|[a-zA-Z_][\w]*)`
	qident   = qi + `(?:\.` + qi + `)?`
	reFrom   = regexp.MustCompile(`(?i)\bFROM\s+(` + qident + `)`)
	reJoin   = regexp.MustCompile(`(?i)\bJOIN\s+(` + qident + `)`)
	reInto   = regexp.MustCompile(`(?i)\bINTO\s+(` + qident + `)`)
	reUpdate = regexp.MustCompile(`(?i)\bUPDATE\s+(` + qident + `)`)
	reTable  = regexp.MustCompile(`(?i)\bTABLE\s+(` + qident + `)`)
	// reUnparsedSource fires when FROM/JOIN is not followed by an identifier or a
	// parenthesized subquery — such a source extracts zero tables and would
	// silently pass an allowlist, so fail closed.
	reUnparsedSource = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s*[^\s(a-zA-Z_"'` + "\x60" + `]`)
	reDanger         = regexp.MustCompile(`(?i)\b(sleep|benchmark|load_file)\s*\(|\b(pg_sleep|into\s+(out|dump)file|copy\s+|\\\\|xp_cmdshell|pg_read_file|lo_import)\b`)
)

// Classify validates and classifies SQL. Fail-closed on anything suspicious.
func Classify(sqlText string) (StatementClass, []string, error) {
	s := strings.TrimSpace(sqlText)
	if s == "" {
		return ClassUnknown, nil, fmt.Errorf("db: empty sql")
	}
	if len(s) > 16<<10 {
		return ClassUnknown, nil, fmt.Errorf("db: sql too large")
	}
	// Null bytes
	if strings.ContainsRune(s, 0) {
		return ClassUnknown, nil, fmt.Errorf("db: null byte in sql")
	}
	// Comments — classic injection / obfuscation vector
	if reCommentLine.MatchString(s) || reCommentBlock.MatchString(s) {
		return ClassUnknown, nil, fmt.Errorf("db: sql comments are not allowed")
	}
	// Multi-statement
	if strings.Contains(s, ";") {
		// allow trailing semicolon only
		trim := strings.TrimSpace(s)
		if strings.Count(trim, ";") > 1 || !strings.HasSuffix(trim, ";") {
			return ClassUnknown, nil, fmt.Errorf("db: multiple statements are not allowed")
		}
		s = strings.TrimSuffix(trim, ";")
		s = strings.TrimSpace(s)
	}
	if reDanger.MatchString(s) {
		return ClassUnknown, nil, fmt.Errorf("db: dangerous sql function/construct blocked")
	}

	// First keyword
	kw := firstKeyword(s)
	var class StatementClass
	switch kw {
	case "SELECT", "WITH", "SHOW":
		class = ClassRead
		toks := scanKeywords(s)
		if kw == "WITH" {
			// Postgres data-modifying CTEs (WITH d AS (DELETE …) SELECT …)
			// execute writes through the read path — reject.
			if toks["INSERT"] || toks["UPDATE"] || toks["DELETE"] {
				return ClassUnknown, nil, fmt.Errorf("db: data-modifying CTE is not a read")
			}
		}
		// SELECT … INTO creates a table; nextval/setval mutate sequences.
		if toks["INTO"] || toks["NEXTVAL"] || toks["SETVAL"] {
			return ClassUnknown, nil, fmt.Errorf("db: read statement contains a write construct")
		}
	case "EXPLAIN":
		// EXPLAIN ANALYZE executes the explained statement — never a read.
		if scanKeywords(s)["ANALYZE"] {
			return ClassUnknown, nil, fmt.Errorf("db: EXPLAIN ANALYZE is not allowed")
		}
		// Only EXPLAIN of a statement that itself classifies as read is allowed.
		inner := strings.TrimSpace(s[len(kw):])
		for {
			ikw := firstKeyword(inner)
			if ikw != "ANALYZE" && ikw != "VERBOSE" {
				break
			}
			inner = strings.TrimSpace(inner[len(ikw):])
		}
		innerClass, _, err := Classify(inner)
		if err != nil || innerClass != ClassRead {
			return ClassUnknown, nil, fmt.Errorf("db: EXPLAIN of non-read statement is not allowed")
		}
		class = ClassRead
	case "INSERT", "UPDATE", "DELETE":
		class = ClassWrite
	case "CREATE", "ALTER", "DROP", "TRUNCATE", "REINDEX", "VACUUM":
		class = ClassDDL
	case "GRANT", "REVOKE", "SET", "RESET", "CALL", "DO", "EXECUTE", "PREPARE", "DEALLOCATE", "LISTEN", "NOTIFY", "UNLISTEN", "COPY":
		class = ClassAdmin
	default:
		return ClassUnknown, nil, fmt.Errorf("db: unsupported statement kind %q", kw)
	}

	// For this phase, DDL/admin are always rejected at classify for app pools.
	// Domain ops can re-check if ever needed for migrations (separate path).
	if class == ClassDDL || class == ClassAdmin {
		return class, nil, fmt.Errorf("db: %s statements are not allowed through app connections", class)
	}

	// Fail closed on table sources we cannot parse — an unparseable FROM/JOIN
	// extracts zero tables and would silently bypass an allowlist.
	if reUnparsedSource.MatchString(s) {
		return ClassUnknown, nil, fmt.Errorf("db: unparseable table source")
	}

	tables := extractTables(s)
	return class, tables, nil
}

func firstKeyword(s string) string {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	j := i
	for j < len(s) {
		r := rune(s[j])
		if unicode.IsLetter(r) || r == '_' {
			j++
			continue
		}
		break
	}
	return strings.ToUpper(s[i:j])
}

func extractTables(s string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(re *regexp.Regexp) {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if len(m) < 2 {
				continue
			}
			t := normalizeIdent(m[1])
			if t == "" || t == "select" {
				continue
			}
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	add(reFrom)
	add(reJoin)
	add(reInto)
	add(reUpdate)
	add(reTable)
	return out
}

func normalizeIdent(s string) string {
	s = strings.TrimSpace(s)
	// strip identifier quoting anywhere (public."users" → public.users)
	s = strings.Map(func(r rune) rune {
		switch r {
		case '"', '\'', '`':
			return -1
		}
		return r
	}, s)
	// strip schema prefix for allowlist match flexibility: public.users → users also checked as full
	return strings.ToLower(s)
}

// scanKeywords returns the set of uppercased word tokens outside string and
// quoted-identifier literals. Comments are already rejected by Classify.
func scanKeywords(s string) map[string]bool {
	out := map[string]bool{}
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			q := c
			i++
			for i < len(s) && s[i] != q {
				i++
			}
			if i < len(s) {
				i++
			}
		case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_':
			j := i
			for j < len(s) {
				r := s[j]
				if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
					j++
					continue
				}
				break
			}
			out[strings.ToUpper(s[i:j])] = true
			i = j
		default:
			i++
		}
	}
	return out
}

var sqlFunctionCallPattern = regexp.MustCompile(`(?i)(?:\b[a-zA-Z_]\w*\s*\.\s*)?\b([a-zA-Z_]\w*)\s*\(`)

var defaultAllowedSQLFunctions = map[string]struct{}{
	"abs": {}, "avg": {}, "ceil": {}, "coalesce": {}, "concat": {},
	"count": {}, "date": {}, "date_trunc": {}, "floor": {}, "greatest": {},
	"least": {}, "length": {}, "lower": {}, "ltrim": {}, "max": {},
	"min": {}, "nullif": {}, "round": {}, "rtrim": {}, "substr": {},
	"substring": {}, "sum": {}, "trim": {}, "upper": {}, "current_date": {},
	"current_time": {}, "current_timestamp": {}, "now": {}, "currval": {},
	"last_insert_rowid": {},
}

// checkFunctions rejects extension and user-defined SQL functions unless the
// pool explicitly allowlists them. This is deliberately conservative: SQL
// classification is not a PostgreSQL parser or a database sandbox.
func checkFunctions(sqlText string, allowed []string) error {
	if strings.TrimSpace(sqlText) == "" {
		return fmt.Errorf("db: empty sql")
	}
	allow := defaultAllowedSQLFunctions
	if len(allowed) > 0 {
		allow = make(map[string]struct{}, len(allowed))
		for _, name := range allowed {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				allow[name] = struct{}{}
			}
		}
	}
	for _, match := range sqlFunctionCallPattern.FindAllStringSubmatchIndex(sqlText, -1) {
		name := strings.ToLower(sqlText[match[2]:match[3]])
		prefix := strings.TrimSpace(sqlText[:match[0]])
		previous := ""
		if fields := strings.Fields(prefix); len(fields) > 0 {
			previous = strings.ToLower(strings.Trim(fields[len(fields)-1], "(),"))
		}
		// These words introduce table, value, or predicate syntax rather than
		// a function invocation.
		switch previous {
		case "from", "join", "into", "update", "table", "values", "in", "exists":
			continue
		}
		if name == "set_config" {
			return fmt.Errorf("db: set_config is not allowed through governed SQL")
		}
		switch name {
		case "values", "in", "exists":
			continue
		}
		if _, ok := allow[name]; !ok {
			return fmt.Errorf("db: SQL function %q is not allowlisted", name)
		}
	}
	return nil
}
