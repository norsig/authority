PROGRAM = "authority"
PREFIX  = "bin"
TEST    ?=./...
TESTARGS ?= -v -race --timeout=40s --parallel=4

default: build test

build: generate
	@sh -c "'$(CURDIR)/scripts/build.sh'"

distribute: generate
	@AUT_DISTRIBUTE=1 sh -c "'$(CURDIR)/scripts/build.sh'"

test: generate
	go test $(TEST) $(TESTARGS) 

generate:
	go generate ./...

updatedeps:
	go get github.com/docopt/docopt-go
	go get github.com/mitchellh/gox
	go get github.com/hashicorp/vault
	go get -t -d -v ./...

.PHONY: default updatedeps generate test build distribute
