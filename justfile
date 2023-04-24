serve:
    go run main.go

test:
    go test -r ./...

cover:
    go test -race -coverprofile=coverage_full.out ./...
    go tool cover -func coverage_full.out