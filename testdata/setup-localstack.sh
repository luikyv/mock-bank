#!/bin/bash

# Exit immediately if any command fails.
set -e

awslocal secretsmanager create-secret \
  --name mockbank/db-credentials \
  --secret-string '{"username":"admin","password":"pass","host":"database.local","port":5432,"dbname":"mockbank","sslmode":"disable"}'

awslocal ssm put-parameter \
  --name "/mockbank/op-signing-key" \
  --type "SecureString" \
  --value "$(cat /keys/op_signing.key)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/mockbank/directory-client-signing-key" \
  --type "SecureString" \
  --value "$(cat /keys/directory_client_signing.key)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/mockbank/directory-client-transport-key" \
  --type "SecureString" \
  --value "$(cat /keys/directory_client_transport.key)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/mockbank/directory-client-transport-cert" \
  --type "SecureString" \
  --value "$(cat /keys/directory_client_transport.crt)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/mockbank/org-signing-key" \
  --type "SecureString" \
  --value "$(cat /keys/org_signing.key)" \
  --overwrite
