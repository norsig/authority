PROGRAM = "authority"
PREFIX  = "bin"
TEST    ?=./...

default: dev test

bin: generate
	@sh -c "'$(CURDIR)/scripts/build.sh'"

test: generate
	go test $(TEST) $(TESTARGS) --timeout=20s --parallel=4

testrace: generate
	go test -race $(TEST) $(TESTARGS)

dev: generate
	@AUT_DEV=1 sh -c "'$(CURDIR)/scripts/build.sh'"

generate:
	go generate ./...

updatedeps:
	go get github.com/docopt/docopt-go
	go get github.com/mitchellh/gox
	go get github.com/hashicorp/vault
	go get -f -u -v ./...

.PHONY: default updatedeps generate test testrace dev bin
