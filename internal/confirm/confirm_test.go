package confirm

import (
	"testing"
	"time"
)

func plan() Plan {
	p := NewPlan("service restart", "lsws", "systemd")
	p.Host = "test-host"
	p.Steps = []Step{{ID: "systemd.restart", Argv: []string{"systemctl", "restart", "lsws"}, Mutates: true}}
	return p
}

func TestTokenRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	p := plan()
	tok := Token(p, now)
	if len(tok) != 16 {
		t.Fatalf("token %q", tok)
	}
	if !Check(p, tok, now) || !Check(p, tok, now.Add(Window)) {
		t.Fatal("token should be valid now and in the next window")
	}
	if Check(p, tok, now.Add(2*Window+time.Second)) {
		t.Fatal("token should expire after two windows")
	}
}

func TestTokenBindsPlan(t *testing.T) {
	now := time.Now()
	p := plan()
	tok := Token(p, now)
	changes := []func(*Plan){
		func(q *Plan) { q.Target = "mariadb" },
		func(q *Plan) { q.Steps[0].Argv[2] = "mariadb" },
		func(q *Plan) { q.Host = "other-host" },
		func(q *Plan) { q.Rollback = "none" },
	}
	for i, ch := range changes {
		q := plan()
		ch(&q)
		if Check(q, tok, now) {
			t.Errorf("change %d: token still valid for a different plan", i)
		}
	}
	if Check(p, "", now) {
		t.Fatal("empty token accepted")
	}
}

func TestEnvelopeHasNoToken(t *testing.T) {
	e := NewEnvelope(plan(), "", "hostops service restart lsws")
	if e.ExitCode != 4 || e.Reason != "missing_token" || e.Status != "confirmation_required" {
		t.Fatalf("%+v", e)
	}
	if NewEnvelope(plan(), "bad", "x").Reason != "token_mismatch_or_expired" {
		t.Fatal("reason for bad token")
	}
}
