.PHONY: help fmt fmt-check tidy-check vet test check \
	js-install js-generate js-generate-check js-wasm js-build js-pack js-check \
	android-init android-aar \
	release npm-publish cli-install

VERSION ?=
TINYGO ?= tinygo
GOMOBILE ?= $(shell go env GOPATH)/bin/gomobile
ANDROID_API ?= 26
JS_DIR := js
ANDROID_DIR := dist/android
ANDROID_AAR := $(ANDROID_DIR)/meshpkt.aar
GOMOBILE_BIN_DIR := $(dir $(GOMOBILE))

help:
	@echo "Available targets:"
	@echo "  make fmt                       Format Go source files"
	@echo "  make check                     Validate Go library"
	@echo "  make cli-install               Install meshpkt-cli to GOPATH/bin"
	@echo "  make js-build                  Build npm package and WASM module"
	@echo "  make js-check                  Build and validate npm package"
	@echo "  make android-init              Install and initialize gomobile"
	@echo "  make android-aar               Build Android AAR library"
	@echo "  make release VERSION=v0.1.0    Create and push a release tag"
	@echo "  make npm-publish               Build and publish the npm package"

fmt:
	gofmt -w .

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "These files need formatting:"; \
		echo "$$files"; \
		exit 1; \
	fi

tidy-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

vet:
	go vet ./...

test:
	go test ./...

check: fmt-check tidy-check vet test

js-install:
	cd $(JS_DIR) && npm ci

js-generate:
	go run ./cmd/gen-ts -out $(JS_DIR)/src/wasm.gen.ts

js-generate-check: js-generate
	git diff --exit-code -- $(JS_DIR)/src/wasm.gen.ts

js-wasm:
	mkdir -p $(JS_DIR)/dist
	$(TINYGO) build \
		-target=wasm \
		-no-debug \
		-opt=z \
		-panic=trap \
		-o $(JS_DIR)/dist/meshpkt.wasm \
		./cmd/meshpkt-wasm
	cp "$$($(TINYGO) env TINYGOROOT)/targets/wasm_exec.js" $(JS_DIR)/dist/

js-build:
	rm -rf $(JS_DIR)/dist
	$(MAKE) js-generate
	$(MAKE) js-install
	cd $(JS_DIR) && npm run build:ts
	$(MAKE) js-wasm

js-pack: js-build
	cd $(JS_DIR) && npm pack --dry-run

js-check: js-build
	git diff --exit-code -- $(JS_DIR)/src/wasm.gen.ts
	cd $(JS_DIR) && npm pack --dry-run

android-init:
	go get -tool golang.org/x/mobile/cmd/gobind
	go install golang.org/x/mobile/cmd/gomobile@latest
	PATH="$(GOMOBILE_BIN_DIR):$$PATH" $(GOMOBILE) init

android-aar:
	mkdir -p $(ANDROID_DIR)
	PATH="$(GOMOBILE_BIN_DIR):$$PATH" $(GOMOBILE) bind \
		-target=android \
		-androidapi $(ANDROID_API) \
		-javapkg cz.meshcore.meshpkt \
		-ldflags="-s -w" \
		-o $(ANDROID_AAR) \
		./mobile

release: check
	@test -n "$(VERSION)" || { \
		echo "Missing VERSION. Example: make release VERSION=v0.1.0"; \
		exit 1; \
	}
	@echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$$' || { \
		echo "Invalid VERSION: $(VERSION). Expected format: v0.1.0"; \
		exit 1; \
	}
	@test "$$(git branch --show-current)" = "main" || { \
		echo "Release must be created from the main branch"; \
		exit 1; \
	}
	@test -z "$$(git status --porcelain)" || { \
		echo "Working tree is not clean"; \
		exit 1; \
	}
	@git fetch --quiet origin main --tags
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" || { \
		echo "Local main is not synchronized with origin/main"; \
		exit 1; \
	}
	@! git rev-parse "$(VERSION)" >/dev/null 2>&1 || { \
		echo "Tag $(VERSION) already exists"; \
		exit 1; \
	}
	cd $(JS_DIR) && npm version --no-git-tag-version "$$(echo '$(VERSION)' | sed 's/^v//')"
	$(MAKE) js-check
	git add $(JS_DIR)/package.json $(JS_DIR)/package-lock.json
	git commit -m "chore: release $(VERSION)"
	git tag -a "$(VERSION)" -m "meshpkt $(VERSION)"
	git push origin main "$(VERSION)"
	@echo "Released $(VERSION)"

cli-install:
	go install ./cmd/meshpkt-cli

npm-publish: js-check
	cd $(JS_DIR) && npm publish --access public
