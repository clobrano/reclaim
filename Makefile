.PHONY: build test vet fmt check

build:
	CGO_ENABLED=0 go build -o reclaim ./cmd/reclaim

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w ." && exit 1)

check: fmt vet test
