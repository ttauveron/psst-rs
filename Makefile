SHELL := /bin/bash
MUSL_TARGET := x86_64-unknown-linux-musl
MUSL_IMAGE := clux/muslrust:stable

.PHONY: help test test-rust test-frontend build-release build-release-alpine

help:
	@printf '%s\n' \
		'Targets:' \
		'  make test             - run Rust and frontend tests' \
		'  make test-rust        - run Rust tests' \
		'  make test-frontend    - run frontend tests with node:test' \
		'  make build-release    - build the release binary' \
		'  make build-release-alpine - build an Alpine-compatible musl release binary via Docker'

test:
	cargo test
	node --test tests/frontend/*.test.mjs

test-rust:
	cargo test

test-frontend:
	node --test tests/frontend/*.test.mjs

build-release:
	cargo build --release

build-release-alpine:
	docker run --rm \
		--user "$$(id -u):$$(id -g)" \
		-e CARGO_HOME=/tmp/cargo-home \
		-e CARGO_TARGET_DIR=/volume/target \
		-v "$$PWD":/volume \
		-w /volume \
		$(MUSL_IMAGE) \
		cargo build --release --target $(MUSL_TARGET)
