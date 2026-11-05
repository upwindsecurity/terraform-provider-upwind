package client

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Vars, not consts, so tests can shrink the budget. Nothing else assigns them.
var (
	consistencyBudget    = 15 * time.Second
	consistencyFirstWait = 200 * time.Millisecond
	consistencyMaxWait   = 2 * time.Second
)

// retryWhileNotFound retries fn while it reports not-found, within the budget.
//
// WRITES ONLY. IsNotFound is what makes Read drop a deleted object from state, so
// wrapping a plain read turns a correct RemoveResource into a 15s stall.
//
// Only a 404 is retried, and only because it means the precondition failed and
// nothing was created. Do NOT extend this to 5xx: a non-idempotent write may have
// stored the object it failed to acknowledge.
//
// On exhaustion the last error is returned untouched, so a wrong id still reads as
// a 404 rather than a timeout.
func retryWhileNotFound[T any](ctx context.Context, op string, fn func(context.Context) (T, error)) (T, error) {
	deadline := time.Now().Add(consistencyBudget)
	wait := consistencyFirstWait

	for attempt := 1; ; attempt++ {
		out, err := fn(ctx)
		if err == nil || !IsNotFound(err) {
			return out, err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return out, err
		}
		if wait > remaining {
			wait = remaining
		}

		// Without this line a retry that fires is invisible under TF_LOG.
		tflog.Debug(ctx, "Not found just after a write; retrying", map[string]any{
			"operation": op, "attempt": attempt, "wait_ms": wait.Milliseconds(),
		})

		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(wait):
		}

		if wait < consistencyMaxWait {
			wait *= 2
		}
	}
}
