package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loreste/loom/adapters/cli"
)

func TestDocumentedCommandsMatchHelpAndManifest(t *testing.T) {
	commands := cli.DocumentedCommands()
	ad, _, errBuf := newTestAdapter(t)
	code := ad.Run(context.Background(), nil)
	if code != 2 {
		t.Fatalf("empty args exit = %d, want 2", code)
	}
	help := errBuf.String()
	for _, top := range commands[""] {
		if !strings.Contains(help, "loom "+top) && !strings.Contains(help, top) {
			// mint-jwt and approve appear in usage lines.
			if !strings.Contains(help, top) {
				t.Fatalf("help missing top-level command %q\n%s", top, help)
			}
		}
	}
	// Recovery subcommands advertised in usage.
	for _, sub := range commands["recovery"] {
		if !strings.Contains(help, sub) {
			t.Fatalf("help missing recovery subcommand %q", sub)
		}
	}
	// Non-existent commands from the pre-hardening changelog must not appear.
	for _, ghost := range []string{"loom operator", "recovery approve", "recovery reject"} {
		if strings.Contains(help, ghost) {
			t.Fatalf("help advertises non-existent command %q", ghost)
		}
	}

	// release-manifest.json must agree with DocumentedCommands.
	manifestPath := filepath.Join("..", "..", "release-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		// When tests run with package dir as cwd, use module-relative path.
		raw, err = os.ReadFile(filepath.Join("..", "..", "release-manifest.json"))
		if err != nil {
			// Try repo root via walk.
			wd, _ := os.Getwd()
			root := wd
			for i := 0; i < 6; i++ {
				candidate := filepath.Join(root, "release-manifest.json")
				if raw, err = os.ReadFile(candidate); err == nil {
					break
				}
				root = filepath.Dir(root)
			}
			if err != nil {
				t.Fatalf("read release-manifest.json: %v (wd=%s)", err, wd)
			}
		}
	}
	var manifest struct {
		CLICommands map[string][]string `json:"cli_commands"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	wantTop := map[string]struct{}{}
	for _, c := range commands[""] {
		wantTop[c] = struct{}{}
	}
	for _, c := range manifest.CLICommands["top_level"] {
		if _, ok := wantTop[c]; !ok {
			t.Fatalf("manifest top_level command %q not in DocumentedCommands", c)
		}
	}
	for group, subs := range commands {
		if group == "" {
			continue
		}
		key := group
		got := manifest.CLICommands[key]
		if len(got) == 0 {
			t.Fatalf("manifest missing cli_commands.%s", key)
		}
		if strings.Join(got, ",") != strings.Join(subs, ",") {
			t.Fatalf("manifest %s = %v, DocumentedCommands = %v", key, got, subs)
		}
	}

	// Unknown top-level command fails.
	errBuf.Reset()
	if code := ad.Run(context.Background(), []string{"operator"}); code == 0 {
		t.Fatal("unknown top-level command must not succeed")
	}
	// Unknown recovery subcommand fails.
	var out bytes.Buffer
	ad.Out = &out
	if code := ad.Run(context.Background(), []string{"recovery", "approve"}); code == 0 {
		t.Fatal("recovery approve must not be implemented")
	}
}
