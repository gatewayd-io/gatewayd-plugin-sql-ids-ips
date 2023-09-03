tidy:
	go mod tidy

build: tidy
	go build -ldflags "-s -w"

checksum:
	sha256sum -b gatewayd-plugin-sql-ids-ips

update-all:
	go get -u ./...
	go mod tidy

build-dev: tidy
	go build
