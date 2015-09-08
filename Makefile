PROGRAM = authority
PREFIX  = bin

default: build test

build: generate
	@CGO_ENABLED=0 godep go build -a -installsuffix cgo -ldflags "-s -X github.com/ovrclk/authority/version.GitCommit=$$(git rev-parse HEAD)" -o $(PREFIX)/$(PROGRAM)
	@cp $(PREFIX)/$(PROGRAM) $(GOPATH)/$(PREFIX)/$(PROGRAM) || true

test: generate
	@godep go test -v ./... -race --timeout=40s

generate:
	@godep go generate ./...

clean:
	@rm -rf bin/*

.PHONY: default build generate test clean
