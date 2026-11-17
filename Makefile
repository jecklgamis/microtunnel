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

# Static, stripped, reproducible Linux binary: no libc/OpenSSL/libyaml needed on the target.
LDFLAGS = -s -w -X main.version=$(BIN_VERSION)
GOBUILD  = CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build test test-race vet fmt fmt-check check image run-shell run test-image \
        test-using-docker integration-test deb rpm clean FORCE

all: build

# Builds ./microtunnel for Linux on the host architecture (it can be cross-built
# from macOS; run it with Docker there).
build:
	$(GOBUILD) -o $(BINARY) $(PKG)
	chmod +x $(BINARY)

# Per-architecture build used by the packages.
build/$(BINARY)-%: FORCE
	@mkdir -p build
	GOARCH=$* $(GOBUILD) -o $@ $(PKG)

# --- tests (run natively; no TUN device or root needed) --------------------------
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

# --- Docker ------------------------------------------------------------------------
image:
	docker build -t $(DOCKER_IMAGE) .

run-shell:
	@docker run -it --entrypoint /bin/bash $(DOCKER_IMAGE)

run:
	@docker run --rm --name microtunnel-peer -it $(DOCKER_IMAGE)

integration-test: image
	./scripts/run-integration-test.sh

# --- packages ----------------------------------------------------------------------
deb: build/$(BINARY)-$(DEB_ARCH)
	rm -rf $(DEB_ROOT)
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/bin
	mkdir -p $(DEB_ROOT)/usr/share/microtunnel
	mkdir -p $(DEB_ROOT)/lib/systemd/system
	mkdir -p $(DEB_ROOT)/etc/microtunnel
	install -m 755 build/$(BINARY)-$(DEB_ARCH) $(DEB_ROOT)/usr/bin/$(BINARY)
	install -m 755 scripts/microtunnel-create-tunnel.sh $(DEB_ROOT)/usr/share/microtunnel/
	install -m 755 scripts/microtunnel-extract-keys-hex.sh $(DEB_ROOT)/usr/bin/
	install -m 755 scripts/microtunnel-extract-pubkey-hex.sh $(DEB_ROOT)/usr/bin/
	install -m 755 scripts/microtunnel-generate-peer-keys.sh $(DEB_ROOT)/usr/bin/
	install -m 755 scripts/microtunnel-create-tunnel.sh $(DEB_ROOT)/usr/bin/
	install -m 644 debian/systemd/microtunnel-relay.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 debian/systemd/microtunnel-peer.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 debian/systemd/microtunnel-peer-1.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 debian/systemd/microtunnel-peer-2.service $(DEB_ROOT)/lib/systemd/system/
	install -m 640 config/relay.yaml $(DEB_ROOT)/etc/microtunnel/relay.yaml
	install -m 640 config/peer.yaml $(DEB_ROOT)/etc/microtunnel/peer.yaml
	install -m 640 config/peer-1.yaml $(DEB_ROOT)/etc/microtunnel/peer-1.yaml
	install -m 640 config/peer-2.yaml $(DEB_ROOT)/etc/microtunnel/peer-2.yaml
	sed -e "s/^Architecture:.*/Architecture: $(DEB_ARCH)/" -e "s/^Version:.*/Version: $(DEB_VERSION)/" debian/control > $(DEB_ROOT)/DEBIAN/control
	install -m 755 debian/postinst $(DEB_ROOT)/DEBIAN/postinst
	install -m 755 debian/prerm $(DEB_ROOT)/DEBIAN/prerm
	dpkg-deb --build --root-owner-group $(DEB_ROOT) build/$(DEB_PKG).deb
	@echo "Package built: build/$(DEB_PKG).deb"

rpm: build/$(BINARY)-$(RPM_GOARCH)
	mkdir -p build/rpm/BUILD build/rpm/RPMS build/rpm/SOURCES build/rpm/SPECS build/rpm/SRPMS
	rpmbuild -bb --target $(RPM_ARCH) \
		--define "_topdir $(CURDIR)/build/rpm" \
		--define "_sourcedir $(CURDIR)" \
		--define "pkg_version $(RPM_VERSION)" \
		--define "pkg_release $(RPM_RELEASE)" \
		--define "bin_path build/$(BINARY)-$(RPM_GOARCH)" \
		rpm/microtunnel.spec
	@echo "Package built: $$(find build/rpm/RPMS -name '*.rpm')"

clean:
	rm -f ./$(BINARY)
	rm -rf build/
