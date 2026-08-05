package db_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

func TestClassifyReadWrite(t *testing.T) {
	c, tables, err := db.Classify("SELECT id, name FROM users WHERE id = $1")
	if err != nil || c != db.ClassRead {
		t.Fatalf("%v %v %v", c, tables, err)
	}
	if len(tables) != 1 || tables[0] != "users" {
		t.Fatalf("tables %v", tables)
	}
	c, _, err = db.Classify("INSERT INTO users (name) VALUES ($1)")
	if err != nil || c != db.ClassWrite {
		t.Fatalf("%v %v", c, err)
	}
}

func TestClassifyRejectsDanger(t *testing.T) {
	cases := []string{
		"SELECT 1; DROP TABLE users",
		"SELECT * FROM users -- bypass",
		"SELECT pg_sleep(10)",
		"DROP TABLE users",
		"COPY users TO STDOUT",
		"",
	}
	for _, s := range cases {
		if _, _, err := db.Classify(s); err == nil {
			t.Fatalf("expected reject: %q", s)
		}
	}
}

func TestClassifyAllowsTrailingSemicolon(t *testing.T) {
	if _, _, err := db.Classify("SELECT 1;"); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyRejectsDataModifyingCTE(t *testing.T) {
	cases := []string{
		// the verified bypass: write hidden in a CTE, executed via the read path
		`WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d`,
		`WITH i AS (INSERT INTO users (name) VALUES ('x') RETURNING *) SELECT * FROM i`,
		`WITH u AS (UPDATE users SET name = 'x' WHERE id = 1 RETURNING *) SELECT * FROM u`,
	}
	for _, s := range cases {
		if c, _, err := db.Classify(s); err == nil {
			t.Fatalf("expected reject (got class %s): %q", c, s)
		}
	}
	// a pure read CTE must still pass
	c, tables, err := db.Classify(`WITH x AS (SELECT id FROM users) SELECT * FROM x`)
	if err != nil || c != db.ClassRead {
		t.Fatalf("read CTE rejected: %v %v %v", c, tables, err)
	}
	// write keywords inside string literals must not false-positive
	c, _, err = db.Classify(`SELECT * FROM users WHERE note = 'delete this'`)
	if err != nil || c != db.ClassRead {
		t.Fatalf("literal keyword false positive: %v %v", c, err)
	}
}

func TestClassifyExplain(t *testing.T) {
	bad := []string{
		// EXPLAIN ANALYZE actually executes the explained statement
		`EXPLAIN ANALYZE DELETE FROM users`,
		`EXPLAIN ANALYZE SELECT * FROM users`,
		`EXPLAIN (ANALYZE, COSTS OFF) SELECT * FROM users`,
		// EXPLAIN of a non-read statement must not pass as read
		`EXPLAIN DELETE FROM users`,
		`EXPLAIN INSERT INTO users (name) VALUES ('x')`,
		`EXPLAIN UPDATE users SET name = 'x'`,
	}
	for _, s := range bad {
		if c, _, err := db.Classify(s); err == nil {
			t.Fatalf("expected reject (got class %s): %q", c, s)
		}
	}
	c, _, err := db.Classify(`EXPLAIN SELECT * FROM users`)
	if err != nil || c != db.ClassRead {
		t.Fatalf("plain EXPLAIN of read rejected: %v %v", c, err)
	}
	if _, _, err := db.Classify(`EXPLAIN VERBOSE SELECT * FROM users`); err != nil {
		t.Fatalf("EXPLAIN VERBOSE of read rejected: %v", err)
	}
}

func TestClassifyRejectsSelectInto(t *testing.T) {
	bad := []string{
		`SELECT * INTO users_backup FROM users`,
		`SELECT id INTO tmp FROM users`,
		`SELECT * FROM users INTO OUTFILE '/tmp/users'`,
	}
	for _, s := range bad {
		if c, _, err := db.Classify(s); err == nil {
			t.Fatalf("expected reject (got class %s): %q", c, s)
		}
	}
	// INSERT INTO is a write and unaffected
	c, _, err := db.Classify(`INSERT INTO users (name) VALUES ('x')`)
	if err != nil || c != db.ClassWrite {
		t.Fatalf("INSERT INTO broken: %v %v", c, err)
	}
}

func TestClassifyRejectsSequenceMutationInRead(t *testing.T) {
	bad := []string{
		`SELECT nextval('users_id_seq')`,
		`SELECT setval('users_id_seq', 42)`,
	}
	for _, s := range bad {
		if c, _, err := db.Classify(s); err == nil {
			t.Fatalf("expected reject (got class %s): %q", c, s)
		}
	}
	// currval does not mutate — stays readable
	if c, _, err := db.Classify(`SELECT currval('users_id_seq')`); err != nil || c != db.ClassRead {
		t.Fatalf("currval rejected: %v %v", c, err)
	}
}

func TestClassifyRejectsDangerConstructs(t *testing.T) {
	cases := []string{
		`SELECT /* inline */ 1`,
		`SELECT 1 /* trailing */`,
		`SELECT pg_read_file('/etc/passwd')`,
		`SELECT load_file('/etc/passwd')`,
		`SELECT xp_cmdshell('dir')`,
		`SELECT lo_import('/etc/passwd')`,
	}
	for _, s := range cases {
		if _, _, err := db.Classify(s); err == nil {
			t.Fatalf("expected reject: %q", s)
		}
	}
}

func TestExecutorRejectsUnallowlistedFunctions(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:function-guard?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if _, err := sqldb.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	reg := db.NewRegistry()
	if err := reg.RegisterDB("main", sqldb, db.Options{AllowedTables: []string{"users"}}); err != nil {
		t.Fatal(err)
	}
	ex, err := reg.ExecutorFor("main", core.Identity{ID: "u"}, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`SELECT dblink_connect('evil')`,
		`SELECT pg_ls_dir('/tmp')`,
		`SELECT set_config('app.tenant_id', 'tenant-b', true)`,
	} {
		if _, err := ex.Query(context.Background(), query); err == nil {
			t.Fatalf("dangerous function was allowed: %s", query)
		}
	}
}

func TestClassifyQuotedIdentifiers(t *testing.T) {
	_, tables, err := db.Classify(`SELECT * FROM "users"`)
	if err != nil || len(tables) != 1 || tables[0] != "users" {
		t.Fatalf("double-quoted: %v %v", tables, err)
	}
	_, tables, err = db.Classify(`SELECT name FROM public."users"`)
	if err != nil || len(tables) != 1 || tables[0] != "public.users" {
		t.Fatalf("schema-qualified quoted: %v %v", tables, err)
	}
	_, tables, err = db.Classify("SELECT * FROM `users`")
	if err != nil || len(tables) != 1 || tables[0] != "users" {
		t.Fatalf("backtick-quoted: %v %v", tables, err)
	}
	_, tables, err = db.Classify(`INSERT INTO "users" (name) VALUES ('x')`)
	if err != nil || len(tables) != 1 || tables[0] != "users" {
		t.Fatalf("quoted insert target: %v %v", tables, err)
	}
	// parenthesized subquery sources still work (inner tables are extracted)
	c, tables, err := db.Classify(`SELECT * FROM (SELECT id FROM users) t`)
	if err != nil || c != db.ClassRead {
		t.Fatalf("subquery source rejected: %v %v %v", c, tables, err)
	}
	if len(tables) != 1 || tables[0] != "users" {
		t.Fatalf("subquery tables: %v", tables)
	}
	// unparseable FROM source fails closed instead of extracting zero tables
	if _, _, err := db.Classify(`SELECT * FROM ?`); err == nil {
		t.Fatal("unparseable FROM source must be rejected")
	}
}

func TestAllowlistEnforcedWithQuotedIdentifiers(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:allowq?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	_, _ = sqldb.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`)
	_, _ = sqldb.Exec(`INSERT INTO users (name) VALUES ('a')`)

	reg := db.NewRegistry()
	if err := reg.RegisterDB("main", sqldb, db.Options{AllowedTables: []string{"allowed"}}); err != nil {
		t.Fatal(err)
	}
	ex, err := reg.ExecutorFor("main", core.Identity{ID: "u"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	// before the fix these extracted zero tables and silently passed the allowlist
	bypasses := []string{
		`SELECT * FROM "users"`,
		`SELECT name FROM public."users"`,
		"SELECT * FROM `users`",
	}
	for _, q := range bypasses {
		if _, err := ex.Query(context.Background(), q); err == nil {
			t.Fatalf("quoted-identifier allowlist bypass succeeded: %q", q)
		}
	}
}

func TestAllowlistAllowsQuotedMatch(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:allowok?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	_, _ = sqldb.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`)
	_, _ = sqldb.Exec(`INSERT INTO users (name) VALUES ('a')`)

	reg := db.NewRegistry()
	if err := reg.RegisterDB("main", sqldb, db.Options{AllowedTables: []string{"users"}}); err != nil {
		t.Fatal(err)
	}
	ex, err := reg.ExecutorFor("main", core.Identity{ID: "u"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ex.Query(context.Background(), `SELECT name FROM "users"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rows) != 1 || rs.Rows[0]["name"] != "a" {
		t.Fatalf("%+v", rs.Rows)
	}
}
