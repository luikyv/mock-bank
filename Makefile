.PHONY: keys

DSN="postgres://admin:pass@localhost:5432/mockbank?sslmode=disable"
ORG_ID="00000000-0000-0000-0000-000000000000"
SOFTWARE_ID="11111111-1111-1111-1111-111111111111"

# Set up the development environment by downloading dependencies installing
# pre-commit hooks, generating keys, and setting up the Open Finance
# Conformance Suite.
setup:
	@go mod download
	@pre-commit install
	@make tools
	@make keys
	@chmod +x testdata/setup-localstack.sh
	@make setup-ui
	@make setup-cs

setup-ui:
	@if [ ! -d "mock-bank-ui" ]; then \
	  echo "Cloning mock-bank-ui repository..."; \
	  git clone git@github.com:luikyv/mock-bank-ui.git mock-bank-ui; \
	fi

tools:
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest
	@go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

lambda-zip:
	@GOOS=linux GOARCH=amd64 go build -o bootstrap ./cmd/server/main.go
	@zip lambda.zip bootstrap
	@rm bootstrap

run:
	@docker-compose up

# Start MockBank along with the Open Finance Conformance Suite.
run-with-cs:
	@docker-compose --profile conformance up

# Generate certificates, private keys, and JWKS files for both the server and clients.
keys:
	@go run cmd/keymaker/main.go --org_id=$(ORG_ID) --software_id=$(SOFTWARE_ID)

models:
	@go generate ./...

# Build the MockBank Docker Image.
build-mockbank:
	@docker-compose build mockbank

build-mockgw:
	@docker-compose build mockgw

migrations:
	@ cd cmd/migration && go run .

# Clone and build the Open Finance Conformance Suite.
setup-cs:
	@if [ ! -d "conformance-suite" ]; then \
	  echo "Cloning open finance conformance suite repository..."; \
	  git clone --branch master --single-branch --depth=1 https://gitlab.com/raidiam-conformance/open-finance/certification.git conformance-suite; \
	fi

	@make build-cs

# Build the Conformance Suite JAR file.
build-cs:
	@docker compose run cs-builder
