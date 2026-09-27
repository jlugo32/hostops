#!/usr/bin/env python3
"""hostops eval runner.

Runs every scenario in evals/scenarios N times with the plugin and N times
without it, using headless Claude Code (`claude -p`, user settings, plugins
and MCP servers switched off), grades each
transcript with the graders defined by expected.json, and writes
evals/RESULTS.md.

Why not `claude plugin eval`? It is early-access and not enabled on every
account. The scenarios also ship graders/*.md in its format, so the same
corpus runs there when available. The graders here implement the same four
types: tool_used, tool_order, regex, and the composite confirm_requested.

Safety: the agent may only call `Bash(hostops *)`. HOSTOPS_FIXTURES is set,
so hostops answers from testdata/hosts and never touches the machine running
the evals. Read/Grep are denied so the agent cannot read real host files.

  run_evals.py --dry                 free: validate corpus, run probes
  run_evals.py [--runs 3] [--model M] [--case GLOB] [--arms with,without]
"""
import argparse
import datetime as dt
import fnmatch
import json
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
SCEN = REPO / "evals" / "scenarios"
BIN = REPO / "bin" / "hostops"
NOW = "2026-09-27T12:00:00Z"


def frontmatter(path):
    text = path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        raise ValueError(f"{path}: no frontmatter")
    meta = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.startswith("  "):
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        try:
            meta[k] = json.loads(v)
        except json.JSONDecodeError:
            meta[k] = v
    return meta, m.group(2).strip()


def scenarios(glob="*"):
    out = []
    for d in sorted(SCEN.iterdir()):
        if d.is_dir() and fnmatch.fnmatch(d.name, glob):
            meta, prompt = frontmatter(d / "prompt.md")
            out.append({"name": d.name, "meta": meta, "prompt": prompt,
                        "exp": json.loads((d / "expected.json").read_text())})
    return out


def hostops_env(fixture, audit):
    env = dict(os.environ)
    env.update({"HOSTOPS_FIXTURES": str(REPO / fixture), "HOSTOPS_NOW": NOW,
                "HOSTOPS_AUDIT_LOG": str(audit), "HOSTOPS_SYSTEM_CONFIG": "/nonexistent",
                "PATH": f"{BIN.parent}:{env.get('PATH', '')}"})
    for k in ("SSH_CLIENT", "SSH_CONNECTION", "HOSTOPS_ADAPTER", "HOSTOPS_READ_ONLY"):
        env.pop(k, None)
    return env


# ---------------------------------------------------------------- dry mode
def dry(scns):
    problems = []
    if subprocess.run([sys.executable, str(REPO / "evals/graders/build_graders.py"), "--check"]).returncode:
        problems.append("graders out of date")
    if len(scns) != 20:
        problems.append(f"expected 20 scenarios, found {len(scns)}")
    for s in scns:
        e, meta = s["exp"], s["meta"]
        if not (REPO / e["fixture"] / "commands.json").exists():
            problems.append(f"{s['name']}: fixture {e['fixture']} missing")
        for k in ("name", "allowed_tools", "runs", "max_turns"):
            if k not in meta:
                problems.append(f"{s['name']}: prompt.md lacks {k}")
        if meta.get("allowed_tools") != ["Bash(hostops *)", "Read", "Grep"]:
            problems.append(f"{s['name']}: allowed_tools must be Bash(hostops *), Read, Grep")
        if e["confirm_required"] and not e["order"]:
            problems.append(f"{s['name']}: write scenario without an observe-before-plan order")
        if not e["probe"]:
            problems.append(f"{s['name']}: no probe commands")
        with tempfile.TemporaryDirectory() as td:
            env = hostops_env(e["fixture"], pathlib.Path(td) / "audit.jsonl")
            for p in e["probe"]:
                argv = p["cmd"].split()
                argv[0] = str(BIN)
                r = subprocess.run(argv, env=env, capture_output=True, text=True, cwd=td)
                if r.returncode != p["exit"]:
                    problems.append(f"{s['name']}: `{p['cmd']}` exit {r.returncode}, want {p['exit']}: {r.stderr[:200]}")
                elif p["stdout"] and p["stdout"] not in r.stdout + r.stderr:
                    problems.append(f"{s['name']}: `{p['cmd']}` output lacks {p['stdout']!r}")
                # every probe that shows evidence must satisfy the scenario's own read patterns
            for rd in e["required_reads"]:
                if not any(re.search(rd, json.dumps({"command": p["cmd"]})) for p in e["probe"]) and \
                   not any(re.search(rd, x) for x in [p["cmd"] for p in e["probe"]]):
                    problems.append(f"{s['name']}: no probe exercises required read {rd!r}")
    for p in problems:
        print("evals --dry:", p, file=sys.stderr)
    print(f"evals --dry: {len(scns)} scenarios, {sum(len(s['exp']['probe']) for s in scns)} probes, "
          f"{'FAIL' if problems else 'OK'}")
    return 1 if problems else 0


# ---------------------------------------------------------------- graders
def tool_calls(events):
    calls = []
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        for b in ev.get("message", {}).get("content", []):
            if b.get("type") == "tool_use":
                calls.append({"tool": b.get("name"), "input": json.dumps(b.get("input", {}))})
    return calls


def total_tokens(events):
    """Sum usage over every assistant message, sub-agents included. A message
    can appear in several stream events, so count each message id once."""
    per = {}
    for ev in events:
        m = ev.get("message") or {}
        if ev.get("type") == "assistant" and m.get("usage"):
            u = m["usage"]
            per[m.get("id") or id(m)] = sum(u.get(k, 0) or 0 for k in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
    return sum(per.values())


def last_message(events):
    for ev in reversed(events):
        if ev.get("type") == "result" and isinstance(ev.get("result"), str):
            return ev["result"]
    for ev in reversed(events):
        if ev.get("type") == "assistant":
            t = [b.get("text", "") for b in ev.get("message", {}).get("content", []) if b.get("type") == "text"]
            if t:
                return "\n".join(t)
    return ""


def matches(call, tool, pat):
    return call["tool"] == tool and re.search(pat, call["input"]) is not None


def grade(exp, calls, final):
    g = []
    for i, p in enumerate(exp["required_reads"]):
        g.append((f"read-{i}", "tool_used", any(matches(c, "Bash", p) for c in calls)))
    for i, (a, b) in enumerate(exp["order"]):
        ia = next((k for k, c in enumerate(calls) if matches(c, "Bash", a)), None)
        ib = next((k for k, c in enumerate(calls) if matches(c, "Bash", b)), None)
        g.append((f"order-{i}", "tool_order", ia is not None and ib is not None and ia < ib))
    for i, p in enumerate(exp["forbidden"]):
        g.append((f"forbid-{i}", "tool_used", not any(matches(c, "Bash", p) for c in calls)))
    confirm = None
    if exp["confirm_required"]:
        dry_ok = any(matches(c, "Bash", r'hostops [^"]*--dry-run') for c in calls)
        no_exec = not any(matches(c, "Bash", "--confirm") for c in calls)
        ask = next(m for m in exp["final_message"] if m["why"].startswith("asks the user to approve"))
        asked = re.search(ask["pattern"], final, re.I if "i" in ask.get("flags", "") else 0) is not None
        confirm = dry_ok and no_exec and asked
        g.append(("confirm_requested", "confirm_requested", confirm))
    for i, m in enumerate(exp["final_message"]):
        if m["why"].startswith("asks the user to approve"):
            continue
        g.append((f"final-{i}", "regex", re.search(m["pattern"], final, re.I if "i" in m.get("flags", "") else 0) is not None))
    return g, confirm


# ---------------------------------------------------------------- runs
def run_once(s, arm, model, idx, outdir):
    meta, exp = s["meta"], s["exp"]
    work = pathlib.Path(tempfile.mkdtemp(prefix=f"hostops-eval-{s['name']}-"))
    env = hostops_env(exp["fixture"], work / "audit.jsonl")
    env.pop("CLAUDECODE", None)
    # Isolation without --bare (which needs an API key): skip user settings
    # (plugins, hooks), load no MCP servers, and run in a fresh directory so
    # project memory is empty. Both arms get the identical setup.
    cmd = ["claude", "-p", s["prompt"], "--setting-sources", "project", "--strict-mcp-config",
           "--mcp-config", '{"mcpServers":{}}', "--output-format", "stream-json", "--verbose",
           "--max-turns", str(meta.get("max_turns", 25)), "--no-session-persistence",
           "--allowedTools", "Bash(hostops *)",
           "--disallowedTools", "Read", "Grep", "Glob", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch",
           "--append-system-prompt", meta.get("append_system_prompt", "")]
    if model:
        cmd += ["--model", model]
    if arm == "with":
        cmd += ["--plugin-dir", str(REPO / "plugin")]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, env=env, cwd=work, capture_output=True, text=True, timeout=meta.get("timeout_seconds", 300))
        raw, err = p.stdout, p.stderr
    except subprocess.TimeoutExpired as te:
        raw, err = (te.stdout or b"").decode() if isinstance(te.stdout, bytes) else (te.stdout or ""), "timeout"
    events = []
    for line in raw.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    calls, final = tool_calls(events), last_message(events)
    res = next((e for e in reversed(events) if e.get("type") == "result"), {})
    tokens = total_tokens(events)
    graders, confirm = grade(exp, calls, final)
    rec = {"scenario": s["name"], "arm": arm, "run": idx, "seconds": round(time.time() - t0, 1),
           "error": (res.get("result") or "is_error") if res.get("is_error") else (None if res else (err.strip()[-500:] or "no result event")),
           "tool_calls": len(calls), "tokens": tokens, "cost_usd": res.get("total_cost_usd"),
           "num_turns": res.get("num_turns"), "graders": [{"name": n, "type": t, "passed": ok} for n, t, ok in graders],
           "success": bool(res) and not res.get("is_error") and all(ok for _, _, ok in graders), "confirm_requested": confirm,
           "calls": calls, "final_message": final}
    (outdir / f"{s['name']}.{arm}.{idx}.json").write_text(json.dumps(rec, indent=2))
    shutil.rmtree(work, ignore_errors=True)
    return rec


def pct(xs):
    xs = [x for x in xs if x is not None]
    return f"{100 * sum(xs) / len(xs):.0f}%" if xs else "n/a"


def mean(xs):
    xs = [x for x in xs if x is not None]
    return f"{statistics.mean(xs):.1f}" if xs else "n/a"


def report(recs, model, runs, outdir):
    arms = [a for a in ("with", "without") if any(r["arm"] == a for r in recs)]
    by = {a: [r for r in recs if r["arm"] == a] for a in arms}
    ver = subprocess.run(["claude", "--version"], capture_output=True, text=True).stdout.strip()
    lines = ["# hostops eval results", "",
             f"Generated {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `make evals` "
             f"(evals/graders/run_evals.py). Model: `{model or 'CLI default'}`. Claude Code: `{ver}`. "
             f"{len({r['scenario'] for r in recs})} scenarios × {runs} runs per arm. Raw transcripts: `{outdir.relative_to(REPO)}` (not committed).", "",
             "Arms: **with** = `claude -p --setting-sources project --strict-mcp-config --plugin-dir plugin`; **without** = the same command without `--plugin-dir`. "
             "Both arms get the same system prompt telling them hostops is on PATH, and both may only run `Bash(hostops *)` against fixture hosts.", "",
             "| Metric | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
    write = lambda a: [r["confirm_requested"] for r in by[a] if r["confirm_requested"] is not None]
    lines.append("| Task success (all graders pass) | " + " | ".join(pct([r["success"] for r in by[a]]) for a in arms) + " |")
    lines.append("| Confirmed-before-destructive (write scenarios) | " + " | ".join(pct(write(a)) for a in arms) + " |")
    lines.append("| Forbidden command attempted | " + " | ".join(pct([any(not g["passed"] for g in r["graders"] if g["name"].startswith("forbid")) for r in by[a]]) for a in arms) + " |")
    lines.append("| Mean tool calls | " + " | ".join(mean([r["tool_calls"] for r in by[a]]) for a in arms) + " |")
    lines.append("| Mean tokens (input+output+cache) | " + " | ".join(mean([r["tokens"] for r in by[a]]) for a in arms) + " |")
    lines.append("| Mean cost (USD, as reported by the CLI) | " + " | ".join(mean([r["cost_usd"] for r in by[a]]) for a in arms) + " |")
    lines.append("| Runs with errors | " + " | ".join(str(sum(1 for r in by[a] if r["error"])) for a in arms) + " |")
    lines += ["", "## Per scenario (task success)", "", "| Scenario | " + " | ".join(arms) + " | failing graders (with) |", "|---|" + "---|" * len(arms) + "---|"]
    for name in sorted({r["scenario"] for r in recs}):
        cells = [pct([r["success"] for r in by[a] if r["scenario"] == name]) for a in arms]
        fails = sorted({g["name"] for r in by.get("with", []) if r["scenario"] == name for g in r["graders"] if not g["passed"]})
        lines.append(f"| {name} | " + " | ".join(cells) + f" | {', '.join(fails) or '-'} |")
    (REPO / "evals" / "RESULTS.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--model", default=os.environ.get("HOSTOPS_EVAL_MODEL", ""))
    ap.add_argument("--case", default="*")
    ap.add_argument("--arms", default="with,without")
    ap.add_argument("--no-report", action="store_true", help="do not rewrite evals/RESULTS.md")
    a = ap.parse_args()
    scns = scenarios(a.case)
    if not BIN.exists():
        sys.exit("build first: make build")
    if a.dry:
        sys.exit(dry(scenarios()))
    outdir = REPO / "evals" / "results" / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir.mkdir(parents=True)
    recs = []
    for s in scns:
        for arm in a.arms.split(","):
            for i in range(a.runs):
                r = run_once(s, arm, a.model, i, outdir)
                print(f"{s['name']:<24} {arm:<8} run {i}: success={r['success']} calls={r['tool_calls']} "
                      f"tokens={r['tokens']} err={r['error'] and r['error'][:80]}", flush=True)
                recs.append(r)
    (outdir / "all.json").write_text(json.dumps(recs, indent=2))
    if not a.no_report:
        report(recs, a.model, a.runs, outdir)


if __name__ == "__main__":
    main()
