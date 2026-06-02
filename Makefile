# ──────────────────────────────────────────────────────────────────────────────
# NetworkSambaScanner – Makefile
# ──────────────────────────────────────────────────────────────────────────────

BINARY      := networksambascanner
CMD_PKG     := ./cmd/networksambascanner
VERSION     := 1.0.0
BUILD_TIME  := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Installation paths
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
SYSCONFDIR  ?= /etc
LOGDIR      ?= /var/log/networksambascanner

# Go tool
GO          ?= go
GOFLAGS     ?=
LDFLAGS     := -s -w \
               -X main.version=$(VERSION) \
               -X main.buildTime=$(BUILD_TIME) \
               -X main.gitCommit=$(GIT_COMMIT)

# Output directory for build artefacts
DIST        := dist

# ── Default target ─────────────────────────────────────────────────────────────
.PHONY: all
all: build

# ── Dependency management ──────────────────────────────────────────────────────
.PHONY: deps
deps:
	$(GO) mod download
	$(GO) mod tidy

# ── Build ──────────────────────────────────────────────────────────────────────
.PHONY: build
build: deps
	@mkdir -p $(DIST)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(CMD_PKG)
	@echo "Built: $(DIST)/$(BINARY)"

# Debug build (no symbol stripping, race detector)
.PHONY: build-debug
build-debug:
	@mkdir -p $(DIST)
	$(GO) build -race -o $(DIST)/$(BINARY)-debug $(CMD_PKG)
	@echo "Debug build: $(DIST)/$(BINARY)-debug"

# ── Cross-compile targets ──────────────────────────────────────────────────────
.PHONY: dist-linux dist-darwin dist-windows release

dist-linux:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-linux-amd64 $(CMD_PKG)
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-linux-arm64 $(CMD_PKG)

dist-darwin:
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-darwin-amd64 $(CMD_PKG)
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-darwin-arm64 $(CMD_PKG)

dist-windows:
	@mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-windows-amd64.exe $(CMD_PKG)

release: dist-linux dist-darwin dist-windows
	@echo "Release artefacts in $(DIST)/"
	@ls -lh $(DIST)/

# ── Test ───────────────────────────────────────────────────────────────────────
.PHONY: test
test:
	$(GO) test ./... -v -timeout 60s

.PHONY: test-short
test-short:
	$(GO) test ./... -short -timeout 30s

.PHONY: bench
bench:
	$(GO) test ./... -bench=. -benchmem

# ── Lint / vet ─────────────────────────────────────────────────────────────────
.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: lint
lint:
	@which golangci-lint > /dev/null 2>&1 || \
		(echo "golangci-lint not found – run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run ./...

# ── Install ────────────────────────────────────────────────────────────────────
.PHONY: install
install: build
	@echo "Installing binary to $(BINDIR)/$(BINARY)"
	install -d $(BINDIR)
	install -m 755 $(DIST)/$(BINARY) $(BINDIR)/$(BINARY)

	@echo "Installing default config to $(SYSCONFDIR)/$(BINARY).yaml"
	install -d $(SYSCONFDIR)
	@if [ ! -f $(SYSCONFDIR)/$(BINARY).yaml ]; then \
		install -m 640 configs/networksambascanner.yaml $(SYSCONFDIR)/$(BINARY).yaml; \
		echo "  Config installed. Edit $(SYSCONFDIR)/$(BINARY).yaml before first use."; \
	else \
		echo "  Config already exists at $(SYSCONFDIR)/$(BINARY).yaml – not overwritten."; \
	fi

	@echo "Creating log directory $(LOGDIR)"
	install -d $(LOGDIR)

	@echo ""
	@echo "Installation complete."
	@echo "  Binary : $(BINDIR)/$(BINARY)"
	@echo "  Config : $(SYSCONFDIR)/$(BINARY).yaml"
	@echo "  Logs   : $(LOGDIR)/"
	@echo ""
	@echo "Next step: edit $(SYSCONFDIR)/$(BINARY).yaml then run:"
	@echo "  $(BINARY)"

# ── Uninstall ──────────────────────────────────────────────────────────────────
.PHONY: uninstall
uninstall:
	@echo "Removing $(BINDIR)/$(BINARY)"
	rm -f $(BINDIR)/$(BINARY)
	@echo "Config file $(SYSCONFDIR)/$(BINARY).yaml left in place (remove manually if desired)."

# ── Install systemd service (optional helper) ──────────────────────────────────
.PHONY: install-service
install-service: install
	@if [ "$(shell id -u)" != "0" ]; then echo "Run as root to install the service"; exit 1; fi
	@echo "[Unit]"                                                    >  /etc/systemd/system/$(BINARY).service
	@echo "Description=NetworkSambaScanner scheduled scan"           >> /etc/systemd/system/$(BINARY).service
	@echo "After=network.target"                                     >> /etc/systemd/system/$(BINARY).service
	@echo ""                                                          >> /etc/systemd/system/$(BINARY).service
	@echo "[Service]"                                                 >> /etc/systemd/system/$(BINARY).service
	@echo "Type=oneshot"                                             >> /etc/systemd/system/$(BINARY).service
	@echo "ExecStart=$(BINDIR)/$(BINARY)"                            >> /etc/systemd/system/$(BINARY).service
	@echo "StandardOutput=append:$(LOGDIR)/systemd.log"             >> /etc/systemd/system/$(BINARY).service
	@echo "StandardError=append:$(LOGDIR)/systemd.log"              >> /etc/systemd/system/$(BINARY).service
	@echo ""                                                          >> /etc/systemd/system/$(BINARY).service
	@echo "[Install]"                                                 >> /etc/systemd/system/$(BINARY).service
	@echo "WantedBy=multi-user.target"                               >> /etc/systemd/system/$(BINARY).service
	@echo "[Unit]"                                                    >  /etc/systemd/system/$(BINARY).timer
	@echo "Description=Run NetworkSambaScanner daily"                >> /etc/systemd/system/$(BINARY).timer
	@echo ""                                                          >> /etc/systemd/system/$(BINARY).timer
	@echo "[Timer]"                                                   >> /etc/systemd/system/$(BINARY).timer
	@echo "OnCalendar=daily"                                         >> /etc/systemd/system/$(BINARY).timer
	@echo "Persistent=true"                                          >> /etc/systemd/system/$(BINARY).timer
	@echo ""                                                          >> /etc/systemd/system/$(BINARY).timer
	@echo "[Install]"                                                 >> /etc/systemd/system/$(BINARY).timer
	@echo "WantedBy=timers.target"                                   >> /etc/systemd/system/$(BINARY).timer
	systemctl daemon-reload
	@echo "Systemd service installed. Enable with: systemctl enable --now $(BINARY).timer"

# ── Clean ──────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -rf $(DIST)
	$(GO) clean ./...

# ── Info ───────────────────────────────────────────────────────────────────────
.PHONY: info
info:
	@echo "Binary    : $(BINARY)"
	@echo "Version   : $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo "Git commit: $(GIT_COMMIT)"
	@echo "GOVERSION : $(shell $(GO) version)"
	@echo "GOPATH    : $(shell $(GO) env GOPATH)"
	@echo "GOMODCACHE: $(shell $(GO) env GOMODCACHE)"

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make              – build the binary (default)"
	@echo "  make build        – build the binary to dist/"
	@echo "  make build-debug  – build with race detector"
	@echo "  make deps         – download and tidy dependencies"
	@echo "  make test         – run all tests"
	@echo "  make vet          – run go vet"
	@echo "  make lint         – run golangci-lint"
	@echo "  make install      – install binary + config (PREFIX=$(PREFIX))"
	@echo "  make uninstall    – remove installed binary"
	@echo "  make release      – cross-compile for Linux/macOS/Windows"
	@echo "  make clean        – remove build artefacts"
	@echo "  make info         – print build information"
