package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

func (a *Adapter) runAuditHead(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	if path == "" {
		fmt.Fprintln(a.errW(), "audit input path required")
		return 2
	}
	events, err := loadAuditEvents(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit head:", err)
		return 1
	}
	if err := audit.VerifyChain(events, strings.TrimSpace(flags["initial-hash"])); err != nil {
		fmt.Fprintln(a.errW(), "audit head: chain invalid")
		return 1
	}
	result := map[string]any{"valid": true, "event_count": len(events)}
	if len(events) > 0 {
		last := events[len(events)-1]
		result["sequence"] = last.Sequence
		result["event_hash"] = last.EventHash
		result["audit_stream"] = last.AuditStream
	}
	return writeJSON(a.outW(), result, a.errW(), "audit head")
}

// runAuditExport filters a bounded JSONL audit stream and verifies its chain
// before writing the selected events. A segment must be checked against a
// trusted hash supplied by the operator, never a hash from the same file.
func (a *Adapter) runAuditExport(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	if path == "" {
		fmt.Fprintln(a.errW(), "audit input path required")
		return 2
	}
	events, err := loadAuditEvents(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit export:", err)
		return 1
	}
	from, to, err := auditRange(flags)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit export:", err)
		return 2
	}
	selected := events
	if from > 0 || to > 0 {
		lower := from
		if lower <= 0 {
			lower = 1
		}
		selected = make([]audit.Event, 0, len(events))
		for _, event := range events {
			if event.Sequence >= lower && (to == 0 || event.Sequence <= to) {
				selected = append(selected, event)
			}
		}
		if to > 0 && int64(len(selected)) != to-lower+1 {
			fmt.Fprintln(a.errW(), "audit export: incomplete sequence range")
			return 1
		}
	}
	if err := audit.VerifyChain(selected, strings.TrimSpace(flags["initial-hash"])); err != nil {
		fmt.Fprintln(a.errW(), "audit export: chain invalid")
		return 1
	}
	encoder := json.NewEncoder(a.outW())
	encoder.SetEscapeHTML(false)
	for _, event := range selected {
		if err := encoder.Encode(event); err != nil {
			fmt.Fprintln(a.errW(), "audit export: output failed")
			return 1
		}
	}
	return 0
}

func (a *Adapter) runAuditCheckpoint(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	if path == "" {
		fmt.Fprintln(a.errW(), "audit input path required")
		return 2
	}
	keyText := strings.TrimSpace(os.Getenv("LOOM_AUDIT_CHECKPOINT_KEY"))
	if keyText == "" {
		fmt.Fprintln(a.errW(), "audit checkpoint requires LOOM_AUDIT_CHECKPOINT_KEY")
		return 2
	}
	key, err := decodeCheckpointKey(keyText)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit checkpoint: invalid key")
		return 2
	}
	events, err := loadAuditEvents(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit checkpoint:", err)
		return 1
	}
	signer, err := audit.NewHMACCheckpointSigner(key)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit checkpoint: invalid key")
		return 2
	}
	checkpoint, err := audit.CreateCheckpoint(events, signer)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit checkpoint: chain invalid")
		return 1
	}
	if err := json.NewEncoder(a.outW()).Encode(checkpoint); err != nil {
		fmt.Fprintln(a.errW(), "audit checkpoint: output failed")
		return 1
	}
	return 0
}

// runAuditRotate creates a new signed checkpoint with the currently supplied
// checkpoint key. Deployments should source this key from a KMS/HSM-backed
// secret and archive the prior checkpoint before rotation.
func (a *Adapter) runAuditRotate(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	if path == "" {
		fmt.Fprintln(a.errW(), "audit input path required")
		return 2
	}
	keyText := strings.TrimSpace(os.Getenv("LOOM_AUDIT_CHECKPOINT_KEY"))
	if keyText == "" {
		fmt.Fprintln(a.errW(), "audit rotate requires LOOM_AUDIT_CHECKPOINT_KEY")
		return 2
	}
	key, err := decodeCheckpointKey(keyText)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit rotate: invalid key")
		return 2
	}
	events, err := loadAuditEvents(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit rotate:", err)
		return 1
	}
	signer, err := audit.NewHMACCheckpointSigner(key)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit rotate: invalid key")
		return 2
	}
	checkpoint, err := audit.CreateCheckpoint(events, signer)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit rotate: chain invalid")
		return 1
	}
	result := map[string]any{"rotated": true, "checkpoint": checkpoint}
	return writeJSON(a.outW(), result, a.errW(), "audit rotate")
}

func auditRange(flags map[string]string) (int64, int64, error) {
	var from, to int64
	var err error
	if value := strings.TrimSpace(flags["from"]); value != "" {
		from, err = strconv.ParseInt(value, 10, 64)
		if err != nil || from <= 0 {
			return 0, 0, fmt.Errorf("--from must be a positive sequence")
		}
	}
	if value := strings.TrimSpace(flags["to"]); value != "" {
		to, err = strconv.ParseInt(value, 10, 64)
		if err != nil || to <= 0 {
			return 0, 0, fmt.Errorf("--to must be a positive sequence")
		}
	}
	if from > 0 && to > 0 && to < from {
		return 0, 0, fmt.Errorf("--to must not precede --from")
	}
	return from, to, nil
}

func decodeCheckpointKey(value string) ([]byte, error) {
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return hex.DecodeString(value)
}

func loadAuditEvents(path string) ([]audit.Event, error) {
	file, err := os.Open(path) // #nosec G304 -- explicit offline operator input
	if err != nil {
		return nil, fmt.Errorf("unable to open input")
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 256<<20))
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	events := make([]audit.Event, 0, 1024)
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("invalid event JSON")
		}
		events = append(events, event)
		if len(events) > 1_000_000 {
			return nil, fmt.Errorf("event limit exceeded")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("input read failed")
	}
	return events, nil
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
