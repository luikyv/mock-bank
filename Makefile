

ORG_ID="00000000-0000-0000-0000-000000000000"
SOFTWARE_ID="11111111-1111-1111-1111-111111111111"
CS_VERSION="6111a8e835350b9270a7443a42329628e62f368f"

setup:
	@chmod +x testdata/setup-localstack.sh
	@make setup-ui

setup-dev:
	@go mod download
	@pre-commit install
	@make setup

# Clone and build the Open Finance Conformance Suite.
setup-cs:
	@if [ ! -d "conformance/suite" ]; then \
	  echo "Cloning open finance conformance suite repository..."; \
	  cd conformance; \
	  git clone https://gitlab.com/raidiam-conformance/open-finance/certification.git suite; \
	  cd suite && git checkout $(CS_VERSION); \
	  echo "Updating httpd/Dockerfile-static to use debian/eol:buster instead of debian:buster..."; \
	  sed -i.bak 's|debian:buster|debian/eol:buster|g' httpd/Dockerfile-static && rm httpd/Dockerfile-static.bak; \
	  docker compose -f ./builder-compose.yml run builder; \
	fi
	
	@if [ ! -d "conformance/suite/venv" ]; then \
	  python3 -m venv conformance/suite/venv; \
	  . ./conformance/suite/venv/bin/activate; \
	  python3 -m pip install httpx; \
	fi

setup-ui:
	@if [ ! -d "mock-bank-ui" ]; then \
	  echo "Cloning mock-bank-ui repository..."; \
	  git clone git@github.com:luikyv/mock-bank-ui.git; \
	fi
	@cd mock-bank-ui && git pull

run:
	@docker compose --profile ui up

# Start MockBank along with the Open Finance Conformance Suite.
run-with-cs:
	@docker compose --profile conformance --profile ui up

# Generate certificates, private keys, and JWKS files for both the server and clients.
keys:
	@go run cmd/keymaker/main.go --org_id=$(ORG_ID) --software_id=$(SOFTWARE_ID) --keys_dir=./keys

models:
	@go generate ./...

migration:
	@docker compose run migration

build:
	@docker compose build

# Build the Conformance Suite JAR file.
build-cs:
	@docker compose -f ./conformance/suite/builder-compose.yml run builder

lint:
	@golangci-lint run ./...

test:
	@go test ./internal/...

test-coverage:
	@go test -coverprofile=coverage.out ./internal/...
	@go tool cover -html="coverage.out" -o coverage.html
	@echo "Total Coverage: `go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+'` %"

cs-tests:
	@conformance/suite/venv/bin/python conformance/suite/scripts/run-test-plan.py \
		no-redirect-payments_test-plan_v2-2 ./conformance/config/phase3_no_redirect_payments_v2-config.json \
		automatic-pix-payments_test-plan_v2-2 ./conformance/config/phase3_automatic_pix_payments_v2-config.json \
		automatic-payments_test-plan_v2-2 ./conformance/config/phase3_automatic_payments_v2-config.json \
		payments_test-plan_v4 ./conformance/config/phase3_payments_v4-config.json \
		--expected-skips-file ./conformance/config/expected_skips.json \
		--expected-failures-file ./conformance/config/expected_failures.json \
		--export-dir ./conformance/results \
		--verbose

cs-tests-wip:
	@conformance/suite/venv/bin/python conformance/suite/scripts/run-test-plan.py \
		no-redirect-payments_test-plan_v2-2 ./conformance/config/phase3_no_redirect_payments_v2-config.json \
		--export-dir ./conformance/results \
		--verbose
