#!/bin/bash
KEY_ID=$(awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --customer-master-key-spec RSA_2048 \
  --description "MockBank OP KMS PS256 key" \
  --query KeyMetadata.KeyId --output text)

echo "Created op key with ID: $KEY_ID"

awslocal kms create-alias --alias-name "alias/mockbank/op-signing-key" --target-key-id "$KEY_ID"

KEY_ID=$(awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --customer-master-key-spec RSA_2048 \
  --description "MockBank Directory Client KMS PS256 key" \
  --query KeyMetadata.KeyId --output text)

echo "Created directory client key with ID: $KEY_ID"

awslocal kms create-alias --alias-name "alias/mockbank/directory-client-signing-key" --target-key-id "$KEY_ID"
