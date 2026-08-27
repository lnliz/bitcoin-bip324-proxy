.PHONY: build test

test:
	go test -v -timeout=2m -race -covermode=atomic -coverprofile=coverage.out -cover -coverpkg=.,./transport,./crypto,./fschacha20 ./...

build:
	go build ./...
