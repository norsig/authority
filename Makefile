PROGRAM = "authority"
PREFIX  = "bin"

default: build test

build: generate
	@godep go build -o $(PREFIX)/$(PROGRAM)

test: generate
	@godep go test -v ./... -race --timeout=40s

generate:
	@godep go generate ./...

clean:
	@rm -rf bin/*

.PHONY: default build generate test clean
