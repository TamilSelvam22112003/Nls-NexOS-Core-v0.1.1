GO ?= go
GOOS ?= linux
GOARCH ?= amd64
BINARY ?= nls-core
LDFLAGS ?= -s -w

.PHONY: build build-static test lint fmt clean
build: build-static

build-static:
	mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/nls-core
	@echo "Built bin/$(BINARY) (GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0)"

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

clean:
	rm -rf bin
