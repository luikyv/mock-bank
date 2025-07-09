.PHONY: keys

ORG_ID="00000000-0000-0000-0000-000000000000"
SOFTWARE_ID="11111111-1111-1111-1111-111111111111"
CS_VERSION="3de7a6d5bccbea655519cd4f3e632bf01f9247d9"

setup:
	@chmod +x testdata/setup-localstack.sh
	@make setup-ui

setup-dev:
	@go mod download
	@pre-commit install
	@make setup

# Clone and build the Open Finance Conformance Suite.
setup-cs:
	@if [ ! -d "conformance-suite" ]; then \
	  echo "Cloning open finance conformance suite repository..."; \
	  git clone https://gitlab.com/raidiam-conformance/open-finance/certification.git conformance-suite; \
	  cd conformance-suite && git checkout $(CS_VERSION); \
	fi

	@make build-cs

setup-ui:
	@if [ ! -d "mock-bank-ui" ]; then \
	  echo "Cloning mock-bank-ui repository..."; \
	  git clone git@github.com:luikyv/mock-bank-ui.git; \
	fi
	@cd mock-bank-ui && git pull

run:
	@docker compose up

# Start MockBank along with the Open Finance Conformance Suite.
run-with-cs:
	@docker compose --profile conformance up

# Generate certificates, private keys, and JWKS files for both the server and clients.
keys:
	@go run cmd/keymaker/main.go --org_id=$(ORG_ID) --software_id=$(SOFTWARE_ID) --keys_dir=./testdata/keys

models:
	@go generate ./...

migration:
	@docker compose run migration

build-mockbank:
	@docker compose build mockbank

build-mockgw:
	@docker compose build mockgw

build-migration:
	@docker compose build migration

# Build the Conformance Suite JAR file.
build-cs:
	@docker compose run cs-builder

test:
	@go test ./internal/...

test-coverage:
	@go test -coverprofile=coverage.out ./internal/...
	@go tool cover -html="coverage.out" -o coverage.html
	@echo "Total Coverage: `go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+'` %"

cs-tests:
	@if [ ! -d "cs-venv" ]; then \
	  python3 -m venv cs-venv; \
	  source cs-venv/bin/activate; \
	  python3 -m pip install httpx; \
	fi

	@cs-venv/bin/python conformance-suite/scripts/run-test-plan.py \
		accounts_test-plan_v2-4 ./testdata/conformance/phase2-config.json \
		--expected-failures-file ./testdata/conformance/expected_failures.json \
		--export-dir ./conformance-suite/results
