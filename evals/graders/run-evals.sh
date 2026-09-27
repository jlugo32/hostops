#!/usr/bin/env bash
# make evals / make evals-dry entry point. See run_evals.py for details.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 evals/graders/run_evals.py "$@"
