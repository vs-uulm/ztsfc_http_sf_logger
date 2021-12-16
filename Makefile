.PHONY: build
build:
	go mod tidy
	go build -v ./cmd/ztsfc_http_sf_logger

.DEFAULT_GOAL := build
