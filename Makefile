.PHONY:	build test

.PHONY: test
test:
	go test -v -p 1 -timeout=1m -race -covermode=atomic -coverprofile=coverage.out -cover -coverpkg=.,./transport,./crypto,./fschacha20 ./...

.PHONY: build
build:
	go build .
