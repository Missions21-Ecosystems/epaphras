.DEFAULT_GOAL := help
DC := docker compose
PY := python3

.PHONY: help up down logs restart test preview once send-now mailpit-test

help: ## Show targets
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-13s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.env:
	cp example.env .env
	@echo "created .env from example.env — fill it in"; exit 1

up: .env ## Build and start the service in the background
	$(DC) up -d --build

down: ## Stop the service (state is kept in the volume)
	$(DC) down

restart: ## Rebuild and restart
	$(DC) up -d --build --force-recreate

logs: ## Follow the service log
	$(DC) logs -f

test: ## Run the unit tests
	$(PY) -m unittest discover -s tests -v

preview: .env ## Read the mailbox read-only and write the digest to data/preview/ (sends nothing, changes nothing)
	DATA_DIR=./data $(PY) -m dmarcd --dry-run

once: .env ## One poll + digest if due, using the container's state volume
	$(DC) run --rm dmarcd --once

send-now: .env ## One poll + send the digest now regardless of DIGEST_TIME
	$(DC) run --rm dmarcd --once --now

mailpit-test: ## Digest the test fixtures and deliver it to a local Mailpit (localhost:1025)
	env -i PATH="$$PATH" HOME="$$HOME" EMAIL=dmarc@example.org PASSWORD=- IMAP_HOST=- \
	  FWD_REPORT_EMAIL=you@example.org SMTP_HOST=localhost SMTP_PORT=1025 SMTP_SECURITY=none SMTP_USER= \
	  DATA_DIR=./data/mailpit-test $(PY) -m dmarcd --env /dev/null --file tests/fixtures/*
