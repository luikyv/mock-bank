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
	@make setup-cs

tools:
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest
	@go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

lambda-zip:
	@GOOS=linux GOARCH=amd64 go build -o main ./cmd/server/main.go
	@zip -r lambda.zip main templates/
	@rm main

# Runs the main MockBank components.
run:
	@make lambda-zip
	@docker volume rm mock-bank_shared
	@docker-compose --profile main up

# Start MockBank along with the Open Finance Conformance Suite.
run-with-cs:
	@make lambda-zip
	@docker volume rm mock-bank_shared
	@docker-compose --profile main --profile conformance up

# Runs only the MockBank dependencies necessary for debugging. With this
# command the MockBank server can run and be debugged in the local host.
debug:
	@docker volume rm mock-bank_shared
	@docker-compose --profile debug up

# Runs the local debug environment with both MockBank and the Conformance
# Suite. With this command the MockBank server can run and be debugged in the
# local host with the Conformance Suite.
debug-with-cs:
	@docker volume rm mock-bank_shared
	@docker-compose --profile debug --profile conformance up

# Run the Conformance Suite.
run-cs:
	@docker-compose --profile conformance up

# Generate certificates, private keys, and JWKS files for both the server and clients.
keys:
	@go run cmd/keymaker/main.go --org_id=$(ORG_ID) --software_id=$(SOFTWARE_ID)

models:
	@oapi-codegen -config ./swaggers/config.yml -package app -o ./internal/api/app/api_gen.go ./swaggers/app.yml
	@oapi-codegen -config ./swaggers/config.yml -package consentv3 -o ./internal/api/consentv3/api_gen.go ./swaggers/consents_v3.yml
	@oapi-codegen -config ./swaggers/config.yml -package accountv2 -o ./internal/api/accountv2/api_gen.go ./swaggers/accounts_v2.yml
	@oapi-codegen -config ./swaggers/config.yml -package resourcev3 -o ./internal/api/resourcev3/api_gen.go ./swaggers/resources_v3.yml

# Build the MockBank Docker Image.
build-mockbank:
	@docker-compose build mockbank

build-mockgw:
	@docker-compose build mockgw

db-migrations:
	@migrate -path ./db/migrations -database "$(DSN)" up

db-migrations-down:
	@migrate -path ./db/migrations -database "$(DSN)" down 1

db-migration-file:
	@read -p "Enter migration name (e.g. add_users_table): " name; \
	migrate create -ext sql -dir ./db/migrations -seq $$name

db-seeds:
	@docker-compose exec -T psql psql -U admin -d mockbank < ./testdata/setup.sql

db-reset:
	@migrate -path ./db/migrations -database "$(DSN)" drop -f
	@migrate -path ./db/migrations -database "$(DSN)" up

# Clone and build the Open Finance Conformance Suite.
setup-cs:
	@if [ ! -d "conformance-suite" ]; then \
	  echo "Cloning open finance conformance suite repository..."; \
	  git clone --branch master --single-branch --depth=1 https://gitlab.com/raidiam-conformance/open-finance/certification.git conformance-suite; \
	fi

# Build the Conformance Suite JAR file.
build-cs:
	@docker compose run cs-builder

# Create a Conformance Suite configuration file using the client keys in /keys.
cs-config:
	@jq -n \
	   --arg clientOneCert "$$(<keys/client_one.crt)" \
	   --arg clientOneKey "$$(<keys/client_one.key)" \
	   --arg clientTwoCert "$$(<keys/client_two.crt)" \
	   --arg clientTwoKey "$$(<keys/client_two.key)" \
	   --argjson clientOneJwks "$$(jq . < keys/client_one.jwks)" \
	   --argjson clientTwoJwks "$$(jq . < keys/client_two.jwks)" \
	   '{ \
		  "alias": "mockbank", \
		  "client": { \
	        "client_id": "client_one", \
			"jwks": $$clientOneJwks \
	      }, \
		  "mtls": { \
		    "cert": $$clientOneCert, \
			"key": $$clientOneKey, \
		  }, \
		  "client2": { \
	        "client_id": "client_two", \
			"jwks": $$clientTwoJwks \
	      }, \
		  "mtls2": { \
		    "cert": $$clientTwoCert, \
			"key": $$clientTwoKey, \
		  }, \
		  "server": { \
			"discoveryUrl": "https://auth.mockbank.local/.well-known/openid-configuration" \
	      }, \
		  "resource": { \
	        "brazilOrganizationId": "00000000-0000-0000-0000-000000000000", \
			"brazilCpf": "12345678901" \
	      }, \
		  "directory": { \
		  	"keystore": "https://keystore.local", \
		    "discoveryUrl": "https://directory.local/.well-known/openid-configuration", \
		    "apibase": "https://directory.local", \
		    "client_id": "random_client" \
		  } \
	    }' > cs_config.json

	@echo "New Conformance Suite config successfully written to cs_config.json"
