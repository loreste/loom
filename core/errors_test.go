package core

import "testing"

func TestReasonInfoForKnownAndUnknown(t *testing.T) {
	msg, hint, retry := ReasonInfoFor(ReasonApprovalRequired)
	if msg == "" || hint == "" || !retry {
		t.Fatalf("approval_required: msg=%q hint=%q retry=%v", msg, hint, retry)
	}
	msg, hint, retry = ReasonInfoFor(ReasonPolicyDeny)
	if msg == "" || hint == "" || retry {
		t.Fatalf("policy_deny: msg=%q hint=%q retry=%v", msg, hint, retry)
	}
	// Unknown reasons fail closed to the internal entry.
	msg, hint, retry = ReasonInfoFor("made_up_reason")
	want := reasonTable[ReasonInternal]
	if msg != want.message || hint != want.hint || retry != want.retryable {
		t.Fatalf("unknown reason must map to internal entry")
	}
}

func TestReasonTableComplete(t *testing.T) {
	reasons := []string{
		ReasonUnauthenticated, ReasonInvalidDelegation, ReasonBoundaryViolation,
		ReasonOperationDenied, ReasonResourceDenied, ReasonFieldDenied,
		ReasonPolicyDeny, ReasonPolicyError, ReasonGuardrail, ReasonRiskBlocked,
		ReasonApprovalRequired, ReasonApprovalDenied, ReasonQuotaExceeded,
		ReasonIdempotencyConflict, ReasonSchemaInvalid, ReasonOperationUnknown,
		ReasonHandlerMissing, ReasonExecutionFailed, ReasonOutputFilter,
		ReasonInternal, ReasonContextCanceled,
	}
	for _, r := range reasons {
		ri, ok := reasonTable[r]
		if !ok {
			t.Errorf("reason %q missing from table", r)
			continue
		}
		if ri.message == "" || ri.hint == "" {
			t.Errorf("reason %q has empty message or hint", r)
		}
	}
}

func TestNewDenialPopulatesHintAndRetryable(t *testing.T) {
	d := NewDenial("quotas", ReasonQuotaExceeded, "rate limit hit", nil)
	if !d.Retryable || d.Hint == "" || d.Message != "rate limit hit" {
		t.Fatalf("got %+v", d)
	}
}

func TestSafeDenialUsesStaticMessage(t *testing.T) {
	d := SafeDenial("execute", ReasonExecutionFailed)
	if d.Message != reasonTable[ReasonExecutionFailed].message {
		t.Fatalf("message not static: %q", d.Message)
	}
	if !d.Retryable || d.Hint == "" {
		t.Fatalf("hint/retryable missing: %+v", d)
	}
}
