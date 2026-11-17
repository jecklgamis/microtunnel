BINARY       := microtunnel
PKG          := ./cmd/microtunnel
DOCKER_IMAGE ?= microtunnel-peer:latest
TEST_IMAGE   ?= microtunnel-test:latest

GO ?= go

# Package versions (overridden by the release workflow from the git tag).
VERSION      ?= 1.0.0
DEB_VERSION  ?= $(VERSION)
DEB_ARCH     ?= amd64
DEB_PKG      := microtunnel_$(DEB_VERSION)_$(DEB_ARCH)
DEB_ROOT     := build/$(DEB_PKG)
RPM_VERSION  ?= $(VERSION)
RPM_RELEASE  ?= 1
RPM_ARCH     ?= x86_64

# Go architecture for each RPM architecture.
RPM_GOARCH   := $(if $(filter aarch64,$(RPM_ARCH)),arm64,amd64)

# Version stamped into the binary (`microtunnel -version`). Package builds stamp
# the package version so the binary and the package always agree.
BIN_VERSION ?= $(VERSION)
deb: BIN_VERSION = $(DEB_VERSION)
rpm: BIN_VERSION = $(RPM_VERSION)
pkg: BIN_VERSION = $(VERSION)

# Static, stripped, reproducible Linux binary: no libc/OpenSSL/libyaml needed on the target.
LDFLAGS = -s -w -X main.version=$(BIN_VERSION)
GOBUILD  = CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build install uninstall linux macos \
        test test-race vet fmt fmt-check check test-image test-using-docker \
        image integration-test dynamic-test enroll-test init-test \
        deb rpm pkg clean FORCE

all: build

# Builds ./microtunnel for the machine you are on (current OS and architecture).
# Override for a cross-build, e.g. `GOOS=linux GOARCH=arm64 make build`.
# On macOS run the result with sudo (creating a utun device needs root).
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)
	chmod +x $(BINARY)

# Builds for this machine, then installs to $(PREFIX)/bin (default /usr/local/bin, which is
# on PATH on macOS). Uses sudo for the copy only when the directory isn't writable, so the
# build itself never runs as root. Override with e.g. `make install PREFIX=$$HOME/.local`.
PREFIX ?= /usr/local
BINDIR  = $(DESTDIR)$(PREFIX)/bin
SUDO    = $(shell d="$(BINDIR)"; while [ ! -e "$$d" ]; do d=$$(dirname "$$d"); done; [ -w "$$d" ] || echo sudo)

install: build
	$(SUDO) install -d $(BINDIR)
	$(SUDO) install -m 755 $(BINARY) $(BINDIR)/$(BINARY)
	@echo "Installed $(BINDIR)/$(BINARY)"
	@echo "On macOS run it with sudo (creating a utun device needs root): sudo microtunnel -c <config>"

uninstall:
	$(SUDO) rm -f $(BINDIR)/$(BINARY)

# Static Linux binaries (no libc needed), one per architecture. The packages use these too.
linux: build/$(BINARY)-linux-amd64 build/$(BINARY)-linux-arm64

build/$(BINARY)-linux-%: FORCE
	@mkdir -p build
	GOARCH=$* $(GOBUILD) -o $@ $(PKG)

# macOS binaries (Apple silicon and Intel).
macos: build/$(BINARY)-darwin-arm64 build/$(BINARY)-darwin-amd64

build/$(BINARY)-darwin-%: FORCE
	@mkdir -p build
	CGO_ENABLED=0 GOOS=darwin GOARCH=$* $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $@ $(PKG)

# --- tests: run natively, no TUN device or root needed ----------------------------
test:
	$(GO) test ./...

test-race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...
	GOOS=linux $(GO) vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@out="$$(gofmt -l cmd internal)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

check: fmt-check vet test-race

test-image:
	docker build -t $(TEST_IMAGE) -f Dockerfile.test .

test-using-docker: test-image
	docker run --rm -v $(CURDIR):/microtunnel -w /microtunnel $(TEST_IMAGE) \
		go test -race -count=1 ./...

# --- Docker image and end-to-end tests (real TUN devices; need Docker) ---------------
image:
	docker build -t $(DOCKER_IMAGE) .

integration-test: image
	./scripts/run-integration-test.sh

# Relay with an empty peers_dir; `peer add/remove` while it runs.
dynamic-test: image
	./scripts/run-dynamic-peers-test.sh

# Admin socket and enrollment service: `peer add -socket`, `join` with a token.
enroll-test: image
	./scripts/run-enroll-test.sh

# `init relay` / `init peer`: one-command setup of a relay and two peers.
init-test: image
	./scripts/run-init-test.sh

# --- packages ----------------------------------------------------------------------
deb: build/$(BINARY)-linux-$(DEB_ARCH)
	rm -rf $(DEB_ROOT)
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/bin
	mkdir -p $(DEB_ROOT)/usr/share/microtunnel/examples
	mkdir -p $(DEB_ROOT)/lib/systemd/system
	mkdir -p $(DEB_ROOT)/etc/microtunnel
	install -d -m 750 $(DEB_ROOT)/etc/microtunnel/peers.d
	install -m 755 build/$(BINARY)-linux-$(DEB_ARCH) $(DEB_ROOT)/usr/bin/$(BINARY)
	install -m 755 scripts/create-tunnel.sh $(DEB_ROOT)/usr/bin/microtunnel-create-tunnel.sh
	install -m 644 packaging/systemd/microtunnel.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 packaging/systemd/microtunnel@.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 packaging/examples/relay.yaml $(DEB_ROOT)/usr/share/microtunnel/examples/relay.yaml
	install -m 644 packaging/examples/peer.yaml $(DEB_ROOT)/usr/share/microtunnel/examples/peer.yaml
	sed -e "s/^Architecture:.*/Architecture: $(DEB_ARCH)/" -e "s/^Version:.*/Version: $(DEB_VERSION)/" packaging/deb/control > $(DEB_ROOT)/DEBIAN/control
	install -m 755 packaging/deb/postinst $(DEB_ROOT)/DEBIAN/postinst
	install -m 755 packaging/deb/prerm $(DEB_ROOT)/DEBIAN/prerm
	dpkg-deb --build --root-owner-group $(DEB_ROOT) build/$(DEB_PKG).deb
	@echo "Package built: build/$(DEB_PKG).deb"

rpm: build/$(BINARY)-linux-$(RPM_GOARCH)
	mkdir -p build/rpm/BUILD build/rpm/RPMS build/rpm/SOURCES build/rpm/SPECS build/rpm/SRPMS
	rpmbuild -bb --target $(RPM_ARCH) \
		--define "_topdir $(CURDIR)/build/rpm" \
		--define "_sourcedir $(CURDIR)" \
		--define "pkg_version $(RPM_VERSION)" \
		--define "pkg_release $(RPM_RELEASE)" \
		--define "bin_path build/$(BINARY)-linux-$(RPM_GOARCH)" \
		packaging/rpm/microtunnel.spec
	@echo "Package built: $$(find build/rpm/RPMS -name '*.rpm')"

# macOS installer: a universal (arm64 + amd64) .pkg. Needs macOS (lipo, pkgbuild,
# productbuild). It is not signed or notarized; see docs/index.md.
PKG_ID  := io.github.jecklgamis.microtunnel
PKG_ROOT := build/pkgroot
PKG_FILE := build/microtunnel-$(VERSION)-universal.pkg

pkg: macos
	rm -rf $(PKG_ROOT)
	mkdir -p $(PKG_ROOT)/usr/local/bin $(PKG_ROOT)/usr/local/share/microtunnel/examples \
		$(PKG_ROOT)/Library/LaunchDaemons $(PKG_ROOT)/etc/newsyslog.d
	lipo -create -output $(PKG_ROOT)/usr/local/bin/$(BINARY) build/$(BINARY)-darwin-arm64 build/$(BINARY)-darwin-amd64
	chmod 755 $(PKG_ROOT)/usr/local/bin/$(BINARY)
	install -m 755 packaging/macos/uninstall.sh $(PKG_ROOT)/usr/local/share/microtunnel/uninstall.sh
	install -m 644 packaging/examples/relay.yaml $(PKG_ROOT)/usr/local/share/microtunnel/examples/relay.yaml
	install -m 644 packaging/examples/peer.yaml $(PKG_ROOT)/usr/local/share/microtunnel/examples/peer.yaml
	install -m 644 packaging/macos/$(PKG_ID).plist $(PKG_ROOT)/Library/LaunchDaemons/$(PKG_ID).plist
	install -m 644 packaging/macos/newsyslog.conf $(PKG_ROOT)/etc/newsyslog.d/microtunnel.conf
	pkgbuild --root $(PKG_ROOT) --identifier $(PKG_ID) --version $(VERSION) \
		--ownership recommended --install-location / --scripts packaging/macos/scripts \
		build/microtunnel-component.pkg
	productbuild --package build/microtunnel-component.pkg $(PKG_FILE)
	@echo "Package built: $(PKG_FILE)"

clean:
	rm -f ./$(BINARY)
	rm -rf build/
