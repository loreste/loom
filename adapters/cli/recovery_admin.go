package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/loreste/loom/core"
)

type recoveryExecuteBody struct {
	Operation        string         `json:"operation"`
	OperationVersion string         `json:"operation_version"`
	Boundary         string         `json:"boundary"`
	Input            map[string]any `json:"input"`
	IdempotencyKey   string         `json:"idempotency_key,omitempty"`
	ApprovalToken    string         `json:"approval_token,omitempty"`
}

func (a *Adapter) operatorHTTPClient() *http.Client {
	if a != nil && a.HTTPClient != nil {
		return a.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (a *Adapter) runRecoveryAdmin(ctx context.Context, command string, args []string) int {
	flags := parseFlags(args)
	base := strings.TrimRight(strings.TrimSpace(flags["url"]), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(os.Getenv("LOOM_URL")), "/")
	}
	if err := validateOperatorURL(base); err != nil {
		fmt.Fprintln(a.errW(), err)
		return 2
	}
	token := strings.TrimSpace(flags["token"])
	if token == "" {
		token = strings.TrimSpace(os.Getenv("LOOM_TOKEN"))
	}
	if token == "" {
		fmt.Fprintln(a.errW(), "recovery operation requires --token or LOOM_TOKEN")
		return 2
	}
	boundary := strings.TrimSpace(flags["boundary"])
	if boundary == "" {
		fmt.Fprintln(a.errW(), "recovery operation requires --boundary")
		return 2
	}
	operation := "recovery." + command
	input := map[string]any{}
	if command == "list" {
		if state := strings.TrimSpace(flags["state"]); state != "" {
			input["state"] = state
		}
		if limit := strings.TrimSpace(flags["limit"]); limit != "" {
			input["limit"] = limit
		}
	} else {
		id := strings.TrimSpace(flags["execution-id"])
		if id == "" {
			fmt.Fprintln(a.errW(), "recovery mutation requires --execution-id")
			return 2
		}
		input["execution_id"] = id
		if reason := strings.TrimSpace(flags["reason"]); reason != "" {
			input["reason"] = reason
		}
	}
	idempotencyKey := strings.TrimSpace(flags["idempotency-key"])
	approvalToken := strings.TrimSpace(flags["approval-token"])
	if command != "list" {
		if idempotencyKey == "" || approvalToken == "" {
			fmt.Fprintln(a.errW(), "recovery mutation requires --idempotency-key and --approval-token")
			return 2
		}
	}
	body, err := json.Marshal(recoveryExecuteBody{Operation: operation, OperationVersion: core.DefaultOperationVersion, Boundary: boundary, Input: input, IdempotencyKey: idempotencyKey, ApprovalToken: approvalToken})
	if err != nil {
		fmt.Fprintln(a.errW(), "recovery operation: request encoding failed")
		return 1
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/execute", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(a.errW(), "recovery operation: request failed")
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.operatorHTTPClient().Do(req)
	if err != nil {
		fmt.Fprintln(a.errW(), "recovery operation request failed")
		return 1
	}
	defer res.Body.Close()
	response, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		fmt.Fprintln(a.errW(), "recovery operation response failed")
		return 1
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		fmt.Fprintf(a.errW(), "recovery operation returned HTTP %d\n", res.StatusCode)
		return 1
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, response, "", "  "); err != nil {
		fmt.Fprintln(a.errW(), "recovery operation response invalid")
		return 1
	}
	fmt.Fprintln(a.outW(), pretty.String())
	return 0
}
