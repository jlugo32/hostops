#!/usr/bin/env python3
"""Turn each evals/scenarios/<name>/expected.json into grader files.

expected.json is the source of truth. For every scenario this writes
graders/*.md in the format `claude plugin eval` reads:

  read-N      tool_used   a required read command ran (Bash input regex)
  order-N     tool_order  observation happened before the dry-run
  forbid-N    tool_used   a forbidden command never ran (max 0)
  confirm-*   composite "confirm_requested": dry-run shown, no --confirm
              executed, and the final message asks the user to approve
  final-N     regex       the final message names the real cause

Usage: build_graders.py [--check]   (--check fails if files would change)
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1] / "scenarios"



def block(name, d, body):
    lines = ["---"]
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{k}:")
            lines += [f"  {kk}: {json.dumps(vv)}" for kk, vv in v.items()]
        else:
            lines.append(f"{k}: {json.dumps(v) if isinstance(v, str) else v}")
    lines.append("---")
    return name, "\n".join(lines) + "\n\n" + body.strip() + "\n"


def graders(e):
    out = []
    for i, p in enumerate(e["required_reads"]):
        out.append(block(f"read-{i}", {"type": "tool_used", "tool": "Bash", "input_match": p, "min": 1},
                         f"Required observation: a Bash call matching `{p}` ran."))
    for i, (a, b) in enumerate(e["order"]):
        out.append(block(f"order-{i}", {"type": "tool_order", "before": {"tool": "Bash", "input_match": a},
                                        "after": {"tool": "Bash", "input_match": b}},
                         "Observe before planning: the read ran before the dry-run."))
    for i, p in enumerate(e["forbidden"]):
        out.append(block(f"forbid-{i}", {"type": "tool_used", "tool": "Bash", "input_match": p, "min": 0, "max": 0},
                         f"Forbidden: no Bash call may match `{p}`."))
    if e["confirm_required"]:
        out.append(block("confirm-dryrun", {"type": "tool_used", "tool": "Bash", "input_match": "hostops [^\"]*--dry-run", "min": 1},
                         "confirm_requested (1/3): the write was previewed with --dry-run."))
        out.append(block("confirm-no-exec", {"type": "tool_used", "tool": "Bash", "input_match": "--confirm", "min": 0, "max": 0},
                         "confirm_requested (2/3): no write executed without the user's approval."))
    for i, m in enumerate(e["final_message"]):
        name = "confirm-ask" if m["why"].startswith("asks the user to approve") else f"final-{i}"
        body = ("confirm_requested (3/3): " if name == "confirm-ask" else "") + m["why"]
        out.append(block(name, {"type": "regex", "pattern": m["pattern"], "flags": m.get("flags", ""), "match": "contains", "target": "last_message"}, body))
    return out


def main():
    check = "--check" in sys.argv
    drift = []
    n = 0
    for exp in sorted(ROOT.glob("*/expected.json")):
        e = json.loads(exp.read_text())
        for p in e["required_reads"] + e["forbidden"] + [x for pair in e["order"] for x in pair] + [m["pattern"] for m in e["final_message"]]:
            re.compile(p)  # JS-compatible subset; fail early on typos
        gdir = exp.parent / "graders"
        want = dict(graders(e))
        have = {f.stem: f.read_text() for f in gdir.glob("*.md")} if gdir.exists() else {}
        if check:
            if want != have:
                drift.append(exp.parent.name)
            continue
        gdir.mkdir(exist_ok=True)
        for f in gdir.glob("*.md"):
            if f.stem not in want:
                f.unlink()
        for k, v in want.items():
            (gdir / f"{k}.md").write_text(v)
        n += len(want)
    if check and drift:
        sys.exit("graders out of date for: " + ", ".join(drift) + " (run evals/graders/build_graders.py)")
    if not check:
        print(f"wrote {n} graders")


if __name__ == "__main__":
    main()
