# hostops — run `make check` before every commit.
GO        ?= go
BIN       := bin/hostops
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
PLUGIN    := plugin

.PHONY: build test test-live lint validate evals evals-dry check clean golden

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/hostops

test:
	$(GO) test -race -count=1 ./...

# Tests that touch a real host. Never run in CI.
test-live:
	HOSTOPS_LIVE=1 $(GO) test -count=1 -run 'Live' ./...

golden:
	HOSTOPS_UPDATE_GOLDEN=1 $(GO) test -count=1 ./internal/cli/...

lint:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo 'gofmt needed' && exit 1)
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null; then golangci-lint run ./...; else echo 'lint: golangci-lint not installed, CI runs it'; fi
	@if command -v shellcheck >/dev/null; then shellcheck scripts/*.sh evals/graders/*.sh; else echo 'lint: shellcheck not installed, CI runs it'; fi

validate:
	bash scripts/check-skills.sh $(PLUGIN)
	@if command -v claude >/dev/null; then claude plugin validate --strict $(PLUGIN) && claude plugin validate --strict .; else echo 'validate: claude CLI not installed, CI runs it'; fi

# Paid: runs the agent. 20 scenarios x 3 runs x (with, without plugin).
evals: build
	bash evals/graders/run-evals.sh

# Free: grades the committed fixtures and checks every scenario is well formed.
evals-dry: build
	bash evals/graders/run-evals.sh --dry

check: lint test validate evals-dry

clean:
	rm -rf bin dist
