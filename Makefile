.PHONY: build test property-test vet check rust-crypto dashboard-build pytools-check package release-assets release-assets-preflight publish-v2 \
       clean install help cross-compile coverage benchmark-ci benchmark-live \
       upstream-audit coverage-touched stress-live soak-24h profile-live release-readiness \
	validate-live-ssh fuzz fuzz-ci upstreams-lock upstreams-update upstream-feature-audit upstream-wiring-audit release-readiness-local \
	release-gate lint-deprecations

# ---------------------------------------------------------------------------
# Version stamping
# ---------------------------------------------------------------------------
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDTIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS   = -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILDTIME)

# Cross-compile target (override with: make cross-compile GOARCH=arm64)
GOARCH   ?= $(shell go env GOARCH)
GOOS     ?= $(shell go env GOOS)

BINDIR   ?= /usr/local/bin

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build:
	go build -ldflags "$(LDFLAGS)" ./...

build-binaries:
	go build -ldflags "$(LDFLAGS)" -o dist/stealthlink-gateway ./cmd/gateway
	go build -ldflags "$(LDFLAGS)" -o dist/stealthlink-agent ./cmd/agent
	go build -ldflags "$(LDFLAGS)" -o dist/stealthlink-tools ./cmd/tools
	go build -ldflags "$(LDFLAGS)" -o dist/stealthlink ./cmd/stealthlink

# ---------------------------------------------------------------------------
# Test / Lint
# ---------------------------------------------------------------------------
test:
	go test ./...

property-test:
	./scripts/run-property-tests.sh 100

vet:
	go vet ./...

coverage:
	go test -cover -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@echo "HTML report: go tool cover -html=coverage.out -o coverage.html"

fuzz:
	@echo "Running fuzzing tests with 30s budget per target..."
	go test -fuzz=FuzzXHTTPMetaDecode -fuzztime=30s ./test/fuzz
	go test -fuzz=FuzzFakeTCPPacketDecode -fuzztime=30s ./test/fuzz
	go test -fuzz=FuzzSmuxFrameParse -fuzztime=30s ./test/fuzz
	go test -fuzz=FuzzConfigYAMLParse -fuzztime=30s ./test/fuzz
	@echo "Fuzzing tests completed successfully"

fuzz-ci:
	@echo "Running fuzzing tests with 120s budget per target..."
	go test -fuzz=FuzzXHTTPMetaDecode -fuzztime=120s ./test/fuzz
	go test -fuzz=FuzzFakeTCPPacketDecode -fuzztime=120s ./test/fuzz
	go test -fuzz=FuzzSmuxFrameParse -fuzztime=120s ./test/fuzz
	go test -fuzz=FuzzConfigYAMLParse -fuzztime=120s ./test/fuzz
	@echo "Fuzzing CI tests completed successfully"

fuzz-long:
	@echo "Running extended fuzzing tests with 2h budget per target..."
	go test -fuzz=FuzzXHTTPMetaDecode -fuzztime=2h ./test/fuzz
	go test -fuzz=FuzzFakeTCPPacketDecode -fuzztime=2h ./test/fuzz
	go test -fuzz=FuzzSmuxFrameParse -fuzztime=2h ./test/fuzz
	go test -fuzz=FuzzConfigYAMLParse -fuzztime=2h ./test/fuzz
	@echo "Extended fuzzing tests completed successfully"

# ---------------------------------------------------------------------------
# Cross-compile
# ---------------------------------------------------------------------------
cross-compile:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o dist/stealthlink-gateway-$(GOOS)-$(GOARCH) ./cmd/gateway
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o dist/stealthlink-agent-$(GOOS)-$(GOARCH) ./cmd/agent
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o dist/stealthlink-tools-$(GOOS)-$(GOARCH) ./cmd/tools
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o dist/stealthlink-$(GOOS)-$(GOARCH) ./cmd/stealthlink

# ---------------------------------------------------------------------------
# Sub-components
# ---------------------------------------------------------------------------
rust-crypto:
	./scripts/build-rust-crypto.sh

dashboard-build:
	@if command -v npm >/dev/null 2>&1; then \
		cd dashboard && npm install && npm run build; \
	else \
		echo "npm not found; skipping dashboard build (set up Node/npm to enable)"; \
	fi

pytools-check:
	python3 -m py_compile tools/*.py

# ---------------------------------------------------------------------------
# Benchmark acceptance gates (CI)
# ---------------------------------------------------------------------------
benchmark-ci:
	@echo "Running benchmark acceptance gate self-test..."
	python3 tools/benchmark_runner.py --ci-selftest --baseline tools/baseline_metrics.json

benchmark-live:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make benchmark-live TARGET=<host>"; exit 1; fi
	python3 tools/benchmark_runner.py "$(TARGET)" --baseline tools/baseline_metrics.json

upstream-audit:
	python3 tools/upstream_delta_scan.py --strict

upstream-feature-audit:
	python3 tools/upstream_feature_verify.py --strict

upstream-wiring-audit:
	python3 tools/upstream_wiring_audit.py --strict --upstreams "conjure,daggerConnect,snowflake,Tunnel,psiphon-tunnel-core,paqet,paqctl,EasyTier,lyrebird,webtunnel"

upstreams-lock:
	python3 tools/upstreams_lock.py --write

upstreams-update:
	python3 tools/upstreams_lock.py --update --write

coverage-touched:
	python3 tools/coverage_touched.py --min 80 --scope-file tools/upstream_scope_packages.txt --baseline tools/baseline_coverage.json --write-baseline-if-missing

stress-live:
	python3 tools/live_validation_runner.py stress

soak-24h:
	python3 tools/live_validation_runner.py soak

profile-live:
	python3 tools/live_validation_runner.py profile

release-readiness-local: upstream-audit upstream-feature-audit upstream-wiring-audit test vet pytools-check
	@echo "Local release readiness checks passed"

release-readiness: release-readiness-local
	python3 tools/live_validation_runner.py release-readiness

validate-live-ssh:
	@if [ -z "$(GATEWAY_HOST)" ] || [ -z "$(AGENT_HOST)" ] || [ -z "$(BUNDLE)" ]; then \
		echo "Usage: make validate-live-ssh GATEWAY_HOST=<ip> AGENT_HOST=<ip> BUNDLE=dist/<zip> [SSH_USER=root] [SSH_KEY=...] [WARP=both|off|builtin|wgquick]"; \
		exit 1; \
	fi
	python3 tools/live_validation_ssh.py --gateway-host "$(GATEWAY_HOST)" --agent-host "$(AGENT_HOST)" --ssh-user "$${SSH_USER:-root}" --ssh-key "$${SSH_KEY:-}" --warp "$${WARP:-both}" --bundle "$(BUNDLE)"

# ---------------------------------------------------------------------------
# Package / Release
# ---------------------------------------------------------------------------
package:
	./scripts/build-release-zip.sh $(VERSION)

release-assets:
	./scripts/build-release-assets.sh --version $(VERSION)

release-assets-preflight:
	./scripts/release-assets-preflight.sh --assets-dir dist/release-assets

release-gate:
	./scripts/release-assets-preflight.sh --assets-dir dist/release-assets --require-live-validation

lint-deprecations:
	@if rg -n '^[[:space:]]*mode:[[:space:]]*legacy([[:space:]]*#.*)?$$' examples/*.yaml; then \
		echo "Legacy runtime mode is deprecated: remove mode: legacy from examples"; \
		exit 1; \
	else \
		echo "No deprecated legacy runtime mode found in examples"; \
	fi

publish-v2:
	./scripts/publish-v2.0.0.sh --repo "$${REPO:-XrayIran/StealthLink}"

package-all: package-linux package-darwin package-windows

package-linux:
	GOOS=linux GOARCH=amd64 $(MAKE) cross-compile
	VERSION=$(VERSION) GOARCH=amd64 ./scripts/build-release-zip.sh
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(MAKE) cross-compile
	VERSION=$(VERSION) GOARCH=arm64 CGO_ENABLED=0 ./scripts/build-release-zip.sh

package-darwin:
	GOOS=darwin GOARCH=amd64 $(MAKE) cross-compile
	VERSION=$(VERSION) GOOS=darwin GOARCH=amd64 ./scripts/build-release-zip.sh
	GOOS=darwin GOARCH=arm64 $(MAKE) cross-compile
	VERSION=$(VERSION) GOOS=darwin GOARCH=arm64 ./scripts/build-release-zip.sh

package-windows:
	GOOS=windows GOARCH=amd64 $(MAKE) cross-compile
	VERSION=$(VERSION) GOOS=windows GOARCH=amd64 ./scripts/build-release-zip.sh

release: build-binaries rust-crypto dashboard-build package
	@echo "Release package ready in dist/"

# ---------------------------------------------------------------------------
# Install / Uninstall
# ---------------------------------------------------------------------------
install: build-binaries
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 dist/stealthlink-gateway $(DESTDIR)$(BINDIR)/stealthlink-gateway
	install -m 0755 dist/stealthlink-agent $(DESTDIR)$(BINDIR)/stealthlink-agent
	install -m 0755 dist/stealthlink-tools $(DESTDIR)$(BINDIR)/stealthlink-tools
	install -m 0755 dist/stealthlink $(DESTDIR)$(BINDIR)/stealthlink
	install -m 0755 scripts/stealthlink-ctl $(DESTDIR)$(BINDIR)/stealthlink-ctl

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean:
	rm -rf dist/ coverage.out coverage.html
	go clean ./...

# ---------------------------------------------------------------------------
# Aggregate targets
# ---------------------------------------------------------------------------
check: test vet pytools-check

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help:
	@echo "StealthLink Makefile targets:"
	@echo ""
	@echo "  build            Build all Go packages (with version stamping)"
	@echo "  build-binaries   Build named binaries into dist/"
	@echo "  test             Run all Go tests"
	@echo "  property-test    Run rapid property tests (100 checks)"
	@echo "  vet              Run go vet"
	@echo "  coverage         Run tests with coverage report"
	@echo "  fuzz             Run fuzzing tests (30s per target)"
	@echo "  fuzz-ci          Run fuzzing tests (120s per target)"
	@echo "  fuzz-long        Run extended fuzzing tests (2h per target)"
	@echo "  cross-compile    Cross-compile binaries (GOOS/GOARCH overridable)"
	@echo "  rust-crypto      Build Rust crypto module"
	@echo "  dashboard-build  Build TypeScript dashboard"
	@echo "  pytools-check    Validate Python tools"
	@echo "  benchmark-ci     Run benchmark acceptance gates"
	@echo "  benchmark-live   Run live benchmark gate (TARGET=<host>)"
	@echo "  upstream-audit   Generate and validate upstream delta matrix"
	@echo "  coverage-touched Enforce touched-package coverage gate"
	@echo "  stress-live      Run stress validation workflow"
	@echo "  soak-24h         Run soak validation workflow"
	@echo "  profile-live     Capture live pprof validation artifacts"
	@echo "  release-readiness Summarize live-validation gate status"
	@echo "  package          Create release ZIP bundle"
	@echo "  release-assets   Prepare publishable release assets (ZIP + helper script)"
	@echo "  release-assets-preflight Validate release asset policy in dist/release-assets"
	@echo "  release-gate     Enforce release assets + live-validation evidence gate"
	@echo "  lint-deprecations Fail if deprecated runtime.mode=legacy appears in examples"
	@echo "  publish-v2       Dry-run v2.0.0-only GitHub publish workflow (set REPO=owner/name)"
	@echo "  package-all      Create release ZIP bundles for all platforms"
	@echo "  package-linux    Create Linux release ZIP bundles"
	@echo "  package-darwin   Create macOS release ZIP bundles"
	@echo "  package-windows  Create Windows release ZIP bundles"
	@echo "  release          Full release: build + rust + dashboard + package"
	@echo "  install          Install binaries to BINDIR (default: /usr/local/bin)"
	@echo "  clean            Remove build artifacts"
	@echo "  check            Run test + vet + pytools-check"
	@echo "  help             Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)  COMMIT=$(COMMIT)  GOARCH=$(GOARCH)  GOOS=$(GOOS)"
