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

func TestCLIDevToolsGated(t *testing.T) {
	t.Setenv("LOOM_DEV_TOOLS", "")
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ad := cli.NewWithPlatform(p)
	var out, errBuf bytes.Buffer
	ad.Out, ad.Err = &out, &errBuf

	code := ad.Run(context.Background(), []string{"approve", "--token=x", "--principal=user:bob", "--op=payment.capture", "--boundary=dev"})
	if code == 0 {
		t.Fatal("approve without LOOM_DEV_TOOLS must fail")
	}
	if !bytes.Contains(errBuf.Bytes(), []byte("LOOM_DEV_TOOLS")) {
		t.Fatalf("expected LOOM_DEV_TOOLS message, got %s", errBuf.String())
	}

	t.Setenv("LOOM_DEV_TOOLS", "1")
	errBuf.Reset()
	out.Reset()
	code = ad.Run(context.Background(), []string{"approve", "--token=dev-appr-1", "--principal=user:bob", "--op=payment.capture", "--boundary=dev"})
	if code != 0 {
		t.Fatalf("approve with LOOM_DEV_TOOLS must work: %s", errBuf.String())
	}
}
