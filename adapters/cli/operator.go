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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) // #nosec G704 -- base is operator-supplied CLI config
	if err != nil {
		fmt.Fprintln(a.errW(), "execution status:", err)
		return 2
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req) // #nosec G704 -- base is operator-supplied CLI config
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

// runAuditExport filters a bounded audit stream and verifies its chain before
// writing the selected events. A segment must be checked against a trusted
// hash supplied by the operator, never a hash from the same source.
//
// With --stream the segment is read from the durable PostgreSQL stream, which
// verifies sequence continuity in the store; with --input it is read from an
// offline JSONL file.
func (a *Adapter) runAuditExport(ctx context.Context, args []string) int {
	flags := parseFlags(args)
	if stream := strings.TrimSpace(flags["stream"]); stream != "" {
		return a.runAuditExportStream(ctx, stream, flags)
	}
	path := strings.TrimSpace(flags["input"])
	if path == "" {
		fmt.Fprintln(a.errW(), "audit export requires --input=/path/audit.jsonl or --stream=<audit-stream>")
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

// runAuditExportStream exports from the durable PostgreSQL audit stream. The
// range is required: an unbounded export would defeat the store's own
// contiguity check, which is what makes a database segment trustworthy.
func (a *Adapter) runAuditExportStream(ctx context.Context, stream string, flags map[string]string) int {
	if a.Platform == nil || a.Platform.AuditExport == nil {
		fmt.Fprintln(a.errW(), "audit export --stream requires LOOM_DATABASE_URL")
		return 2
	}
	from, to, err := auditRange(flags)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit export:", err)
		return 2
	}
	if from <= 0 || to <= 0 {
		fmt.Fprintln(a.errW(), "audit export --stream requires --from and --to")
		return 2
	}
	events, err := a.Platform.AuditExport.ExportStream(ctx, stream, from, to, strings.TrimSpace(flags["initial-hash"]))
	if err != nil {
		fmt.Fprintln(a.errW(), "audit export:", err)
		return 1
	}
	encoder := json.NewEncoder(a.outW())
	encoder.SetEscapeHTML(false)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			fmt.Fprintln(a.errW(), "audit export: output failed")
			return 1
		}
	}
	return 0
}

// checkpointSigner loads an HMAC signer from the named environment variable.
// Checkpoint keys are read only from the environment so they never appear in
// a process listing or shell history.
func (a *Adapter) checkpointSigner(command, env string) (*audit.HMACCheckpointSigner, int) {
	keyText := strings.TrimSpace(os.Getenv(env))
	if keyText == "" {
		fmt.Fprintf(a.errW(), "%s requires %s\n", command, env)
		return nil, 2
	}
	key, err := decodeCheckpointKey(keyText)
	if err != nil {
		fmt.Fprintf(a.errW(), "%s: invalid key in %s\n", command, env)
		return nil, 2
	}
	signer, err := audit.NewHMACCheckpointSigner(key)
	if err != nil {
		fmt.Fprintf(a.errW(), "%s: invalid key in %s\n", command, env)
		return nil, 2
	}
	return signer, 0
}

func (a *Adapter) runAuditCheckpoint(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	if path == "" {
		fmt.Fprintln(a.errW(), "audit input path required")
		return 2
	}
	signer, code := a.checkpointSigner("audit checkpoint", checkpointKeyEnv)
	if code != 0 {
		return code
	}
	events, err := loadAuditEvents(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit checkpoint:", err)
		return 1
	}
	checkpoint, err := audit.CreateCheckpoint(events, signer)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit checkpoint: chain invalid")
		return 1
	}
	return writeJSON(a.outW(), checkpoint, a.errW(), "audit checkpoint")
}

// runAuditVerifyCheckpoint checks a stored checkpoint against the events it
// claims to attest. Without this an auditor holding a signed checkpoint has no
// way to confirm it with the tool that produced it.
func (a *Adapter) runAuditVerifyCheckpoint(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	checkpointPath := strings.TrimSpace(flags["checkpoint"])
	if path == "" || checkpointPath == "" {
		fmt.Fprintln(a.errW(), "audit verify-checkpoint requires --input and --checkpoint")
		return 2
	}
	signer, code := a.checkpointSigner("audit verify-checkpoint", checkpointKeyEnv)
	if code != 0 {
		return code
	}
	events, err := loadAuditEvents(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit verify-checkpoint:", err)
		return 1
	}
	checkpoint, err := loadCheckpoint(checkpointPath)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit verify-checkpoint:", err)
		return 1
	}
	if err := audit.VerifyCheckpoint(events, checkpoint, signer); err != nil {
		fmt.Fprintln(a.errW(), "audit verify-checkpoint: invalid")
		return 1
	}
	result := map[string]any{
		"valid":           true,
		"event_count":     checkpoint.EventCount,
		"last_event_hash": checkpoint.LastEventHash,
	}
	return writeJSON(a.outW(), result, a.errW(), "audit verify-checkpoint")
}

// runAuditRotate re-signs an existing checkpoint with a new key. It verifies
// the prior checkpoint with the retired key first: re-signing without that
// check would let a holder of only the new key attest to a chain that was
// never covered by the old one, which is the continuity rotation exists to
// preserve.
func (a *Adapter) runAuditRotate(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	checkpointPath := strings.TrimSpace(flags["checkpoint"])
	if path == "" || checkpointPath == "" {
		fmt.Fprintln(a.errW(), "audit rotate requires --input and --checkpoint")
		return 2
	}
	previous, code := a.checkpointSigner("audit rotate", previousCheckpointKeyEnv)
	if code != 0 {
		return code
	}
	next, code := a.checkpointSigner("audit rotate", checkpointKeyEnv)
	if code != 0 {
		return code
	}
	events, err := loadAuditEvents(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit rotate:", err)
		return 1
	}
	priorCheckpoint, err := loadCheckpoint(checkpointPath)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit rotate:", err)
		return 1
	}
	if err := audit.VerifyCheckpoint(events, priorCheckpoint, previous); err != nil {
		fmt.Fprintln(a.errW(), "audit rotate: prior checkpoint is not valid under the retired key")
		return 1
	}
	rotated, err := audit.CreateCheckpoint(events, next)
	if err != nil {
		fmt.Fprintln(a.errW(), "audit rotate: chain invalid")
		return 1
	}
	result := map[string]any{"rotated": true, "checkpoint": rotated}
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

const (
	checkpointKeyEnv         = "LOOM_AUDIT_CHECKPOINT_KEY"
	previousCheckpointKeyEnv = "LOOM_AUDIT_CHECKPOINT_KEY_PREVIOUS"
	maxCheckpointBytes       = 64 << 10
)

func loadCheckpoint(path string) (audit.Checkpoint, error) {
	file, err := os.Open(path) // #nosec G304 -- explicit offline operator input
	if err != nil {
		return audit.Checkpoint{}, fmt.Errorf("unable to open checkpoint")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxCheckpointBytes+1))
	if err != nil {
		return audit.Checkpoint{}, fmt.Errorf("checkpoint read failed")
	}
	if int64(len(raw)) > maxCheckpointBytes {
		return audit.Checkpoint{}, fmt.Errorf("checkpoint exceeds size limit")
	}
	var checkpoint audit.Checkpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return audit.Checkpoint{}, fmt.Errorf("invalid checkpoint JSON")
	}
	return checkpoint, nil
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
