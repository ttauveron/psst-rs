SHELL := /bin/bash
MUSL_TARGET := x86_64-unknown-linux-musl
MUSL_IMAGE := clux/muslrust:stable

.PHONY: help test test-rust test-frontend build-release build-release-alpine package-binary terraform-init terraform-plan terraform-apply terraform-output ansible-syntax ansible-deploy deploy deploy-no-terraform check-env check-cloudflare-env

help:
	@printf '%s\n' \
		'Targets:' \
		'  make test             - run Rust and frontend tests' \
		'  make test-rust        - run Rust tests' \
		'  make test-frontend    - run frontend tests with node:test' \
		'  make build-release    - build the release binary' \
		'  make build-release-alpine - build an Alpine-compatible musl release binary via Docker' \
		'  make package-binary   - copy the Alpine-compatible release binary into ansible/files/bin/psst-rs' \
		'  make terraform-init   - run tofu init in terraform/' \
		'  make terraform-plan   - run tofu plan in terraform/' \
		'  make terraform-apply  - run tofu apply in terraform/' \
		'  make terraform-output - print tofu outputs as JSON' \
		'  make ansible-syntax   - run ansible syntax check' \
		'  make ansible-deploy   - run the Ansible playbook using secrets from .env' \
		'  make deploy           - build binary, apply Terraform, then deploy with Ansible' \
		'  make deploy-no-terraform - build binary, then deploy with Ansible only'

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

package-binary: build-release-alpine
	install -m 0755 target/$(MUSL_TARGET)/release/psst-rs ansible/files/bin/psst-rs

terraform-init:
	@set -a; \
		if [ -f ./.env ]; then . ./.env; fi; \
		set +a; \
		cd terraform && tofu init

check-cloudflare-env:
	@set -a; \
		if [ -f ./.env ]; then . ./.env; fi; \
		set +a; \
		test -n "$$CLOUDFLARE_API_TOKEN" || { echo "Missing CLOUDFLARE_API_TOKEN in .env"; exit 1; }

terraform-plan: check-cloudflare-env
	@set -a; \
		if [ -f ./.env ]; then . ./.env; fi; \
		set +a; \
		cd terraform && tofu plan

terraform-apply: check-cloudflare-env
	@set -a; \
		if [ -f ./.env ]; then . ./.env; fi; \
		set +a; \
		cd terraform && tofu apply

terraform-output:
	@set -a; \
		if [ -f ./.env ]; then . ./.env; fi; \
		set +a; \
		cd terraform && tofu output -json

check-env:
	@set -a; \
		if [ -f ./.env ]; then . ./.env; fi; \
		set +a; \
		test -n "$$PSST_TURNSTILE_SITE_KEY" || { echo "Missing PSST_TURNSTILE_SITE_KEY in .env"; exit 1; }; \
		test -n "$$PSST_TURNSTILE_SECRET_KEY" || { echo "Missing PSST_TURNSTILE_SECRET_KEY in .env"; exit 1; }

ansible-syntax:
	cd ansible && ansible-playbook --syntax-check site.yml

ansible-deploy: check-env
	@set -a; \
		if [ -f ./.env ]; then . ./.env; fi; \
		set +a; \
		cd ansible && ansible-playbook site.yml --ask-become-pass

deploy: package-binary terraform-apply ansible-deploy

deploy-no-terraform: package-binary ansible-deploy
