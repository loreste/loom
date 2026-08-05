package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/loreste/loom/adapters/cli"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
)

func newTestAdapter(t *testing.T) (*cli.Adapter, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ad := cli.New(p.Runtime)
	var out, errBuf bytes.Buffer
	ad.Out = &out
	ad.Err = &errBuf
	return ad, &out, &errBuf
}

func TestCLIDenyByDefaultNoToken(t *testing.T) {
	t.Setenv("LOOM_TOKEN", "")
	ad, out, errBuf := newTestAdapter(t)
	code := ad.Run(context.Background(), []string{
		"exec", "document.read",
		"--boundary=dev",
		"--resource-type=document", "--resource-id=1",
		`--input={"id":"1"}`,
	})
	if code == 0 {
		t.Fatalf("no credentials must fail, out=%s err=%s", out, errBuf)
	}
	var resp core.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("expected denial response JSON, got %q: %v", out, err)
	}
	if resp.Allowed {
		t.Fatal("no credentials must deny")
	}
}

func TestCLIAllowWithGrantedPrincipal(t *testing.T) {
	t.Setenv("LOOM_TOKEN", "")
	ad, out, errBuf := newTestAdapter(t)
	code := ad.Run(context.Background(), []string{
		"exec", "document.read",
		"--boundary=dev",
		"--token=alice-secret-token",
		"--resource-type=document", "--resource-id=1",
		`--input={"id":"1"}`,
	})
	if code != 0 {
		t.Fatalf("granted exec must exit 0, got %d out=%s err=%s", code, out, errBuf)
	}
	var resp core.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("response JSON: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("granted principal must allow: %+v", resp.Denial)
	}
}
