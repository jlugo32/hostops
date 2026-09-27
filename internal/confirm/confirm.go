// Package confirm implements the confirmation-token protocol (ADR-0003).
//
// A write command first runs with --dry-run. That prints a Plan: the exact
// argv of every step, the target, the blast radius, the rollback and a
// confirm_token. The token is a hash over the canonical plan plus a coarse
// time window and the host name, so it only authorizes that exact plan, on
// that host, for a short time. Running the write without a valid token exits
// 4 and prints an Envelope on stderr instead of acting.
package confirm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/jlugo32/hostops/internal/hosterr"
)

// Window is the token time bucket. A token is valid in the bucket it was
// minted in and the next one, i.e. for between Window and 2*Window.
const Window = 15 * time.Minute

// Step is one command the plan would run.
type Step struct {
	ID      string   `json:"id"`
	Argv    []string `json:"argv"`
	Mutates bool     `json:"mutates"`
}

// Plan describes a write before it happens.
type Plan struct {
	Schema      string   `json:"schema"`
	Command     string   `json:"command"`
	Target      string   `json:"target"`
	Adapter     string   `json:"adapter"`
	Host        string   `json:"host"`
	Steps       []Step   `json:"steps"`
	Diff        []string `json:"dry_run_diff"`
	BlastRadius string   `json:"blast_radius"`
	Rollback    string   `json:"rollback"`
	Verify      string   `json:"verify"`
}

// NewPlan fills the schema and host fields.
func NewPlan(command, target, adapter string) Plan {
	h, _ := os.Hostname()
	return Plan{Schema: "hostops.plan.v1", Command: command, Target: target, Adapter: adapter, Host: h, Diff: []string{}}
}

func bucket(t time.Time) int64 { return t.Unix() / int64(Window/time.Second) }

func tokenFor(p Plan, b int64) string {
	canon, _ := json.Marshal(p) // struct field order is fixed, so this is canonical
	h := sha256.New()
	h.Write([]byte("hostops-confirm-v1\x00"))
	h.Write(canon)
	var nb [8]byte
	for i := 0; i < 8; i++ {
		nb[i] = byte(b >> (8 * i))
	}
	h.Write(nb[:])
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Token mints the token for p at time now.
func Token(p Plan, now time.Time) string { return tokenFor(p, bucket(now)) }

// Check reports whether given authorizes p at time now.
func Check(p Plan, given string, now time.Time) bool {
	if given == "" {
		return false
	}
	b := bucket(now)
	return given == tokenFor(p, b) || given == tokenFor(p, b-1)
}

// DryRun is what --dry-run prints on stdout.
type DryRun struct {
	Plan
	ConfirmToken string `json:"confirm_token"`
	ExpiresAfter string `json:"expires_after"`
	NextStep     string `json:"next_step"`
}

// Envelope is what a write without a valid token prints on stderr (exit 4).
// It deliberately carries no token: the caller must run --dry-run and read
// the plan to get one.
type Envelope struct {
	Schema   string `json:"schema"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	ExitCode int    `json:"exit_code"`
	Plan     Plan   `json:"plan"`
	NextStep string `json:"next_step"`
}

// NewDryRun wraps p with a fresh token.
func NewDryRun(p Plan, invocation string, now time.Time) DryRun {
	tok := Token(p, now)
	return DryRun{
		Plan:         p,
		ConfirmToken: tok,
		ExpiresAfter: "15-30 minutes, or as soon as the plan changes",
		NextStep:     invocation + " --confirm=" + tok,
	}
}

// NewEnvelope builds the exit-4 envelope.
func NewEnvelope(p Plan, given, invocation string) Envelope {
	reason := "missing_token"
	if given != "" {
		reason = "token_mismatch_or_expired"
	}
	return Envelope{
		Schema:   "hostops.confirm.v1",
		Status:   "confirmation_required",
		Reason:   reason,
		ExitCode: hosterr.Confirm,
		Plan:     p,
		NextStep: "review this plan, then run: " + invocation + " --dry-run  (it prints confirm_token)",
	}
}

// ErrRequired is the typed error behind exit code 4.
func ErrRequired(reason string) error {
	return hosterr.New(hosterr.Confirm, "confirmation required (%s)", reason)
}
