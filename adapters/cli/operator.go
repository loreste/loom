package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/loreste/loom/audit"
)

func (a *Adapter) runExecutionGet(ctx context.Context, args []string) int {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(a.errW(), "execution ID required")
		return 2
	}
	flags := parseFlags(args[1:])
	base := strings.TrimRight(strings.TrimSpace(flags["url"]), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(os.Getenv("LOOM_URL")), "/")
	}
	token := strings.TrimSpace(flags["token"])
	if token == "" {
		token = strings.TrimSpace(os.Getenv("LOOM_TOKEN"))
	}
	if err := validateOperatorURL(base); err != nil {
		fmt.Fprintln(a.errW(), err)
		return 2
	}
	if token == "" {
		fmt.Fprintln(a.errW(), "execution status requires --token or LOOM_TOKEN")
		return 2
	}
	endpoint := base + "/v1/executions/" + url.PathEscape(args[0])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		fmt.Fprintln(a.errW(), "execution status:", err)
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(a.errW(), "execution status request failed")
		return 1
	}
	defer res.Body.Close()
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		fmt.Fprintf(a.errW(), "execution status returned HTTP %d\n", res.StatusCode)
		return 1
	}
	var value json.RawMessage
	if err := json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&value); err != nil {
		fmt.Fprintln(a.errW(), "execution status response invalid")
		return 1
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, value, "", "  "); err != nil {
		fmt.Fprintln(a.errW(), "execution status response invalid")
		return 1
	}
	fmt.Fprintln(a.outW(), pretty.String())
	return 0
}

func (a *Adapter) runAuditVerify(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	if path == "" {
		fmt.Fprintln(a.errW(), "audit input path required")
		return 2
	}
	// The path is an explicit local operator argument to an offline command;
	// it is not derived from a request or used by a server handler.
	file, err := os.Open(path) // #nosec G304 -- intentional offline operator input
	if err != nil {
		fmt.Fprintln(a.errW(), "audit verify: unable to open input")
		return 1
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 256<<20))
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	events := make([]audit.Event, 0, 1024)
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			fmt.Fprintln(a.errW(), "audit verify: invalid event JSON")
			return 1
		}
		events = append(events, event)
		if len(events) > 1_000_000 {
			fmt.Fprintln(a.errW(), "audit verify: event limit exceeded")
			return 1
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(a.errW(), "audit verify: input read failed")
		return 1
	}
	if err := audit.VerifyChain(events, strings.TrimSpace(flags["initial-hash"])); err != nil {
		fmt.Fprintln(a.errW(), "audit verify: chain invalid")
		return 1
	}
	result := map[string]any{"valid": true, "event_count": len(events)}
	if len(events) > 0 {
		result["last_event_hash"] = events[len(events)-1].EventHash
	}
	encoded, _ := json.Marshal(result)
	fmt.Fprintln(a.outW(), string(encoded))
	return 0
}

func validateOperatorURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("--url or LOOM_URL must be an absolute URL")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return fmt.Errorf("operator URL must use HTTPS outside localhost")
	}
	return nil
}
