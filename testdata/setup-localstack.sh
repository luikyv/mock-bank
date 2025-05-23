#!/bin/bash

rm -f /shared/mockbank_url.txt

# Exit immediately if any command fails.
set -e

OP_KEY_ID=$(awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --customer-master-key-spec RSA_2048 \
  --description "MockBank OP KMS PS256 key" \
  --query KeyMetadata.KeyId --output text)
awslocal kms create-alias --alias-name "alias/mockbank-op-signing-key" --target-key-id "$OP_KEY_ID"

DIRECTORY_CLIENT_KEY_ID=$(awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --customer-master-key-spec RSA_2048 \
  --description "MockBank Directory Client KMS PS256 key" \
  --query KeyMetadata.KeyId --output text)
awslocal kms create-alias --alias-name "alias/mockbank-directory-client-signing-key" --target-key-id "$DIRECTORY_CLIENT_KEY_ID"

awslocal secretsmanager create-secret \
  --name mockbank/db-credentials \
  --secret-string 'postgres://admin:pass@psql.local:5432/mockbank?sslmode=disable'

awslocal iam create-role \
  --role-name mockbank-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }'

awslocal kms put-key-policy \
  --key-id "$OP_KEY_ID" \
  --policy-name default \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::000000000000:role/mockbank-lambda-role"},
        "Action": [
          "kms:Sign",
          "kms:GetPublicKey"
        ],
        "Resource": "*"
      }
    ]
  }'

awslocal kms put-key-policy \
  --key-id "$DIRECTORY_CLIENT_KEY_ID" \
  --policy-name default \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::000000000000:role/mockbank-lambda-role"},
        "Action": [
          "kms:Sign",
          "kms:GetPublicKey"
        ],
        "Resource": "*"
      }
    ]
  }'

awslocal iam put-role-policy \
  --role-name mockbank-lambda-role \
  --policy-name allow-access-to-db-secret \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }]
  }'

awslocal lambda create-function \
  --function-name mockbank-lambda \
  --runtime go1.x \
  --handler main \
  --role arn:aws:iam::000000000000:role/mockbank-lambda-role \
  --zip-file fileb:///tmp/lambda.zip

API_ID=$(awslocal apigateway create-rest-api --name "proxy-api" --query 'id' --output text)
ROOT_ID=$(awslocal apigateway get-resources --rest-api-id "$API_ID" --query 'items[0].id' --output text)
PROXY_ID=$(awslocal apigateway create-resource \
  --rest-api-id "$API_ID" \
  --parent-id "$ROOT_ID" \
  --path-part "{proxy+}" \
  --query 'id' \
  --output text)

awslocal apigateway put-method \
  --rest-api-id "$API_ID" \
  --resource-id "$PROXY_ID" \
  --http-method ANY \
  --authorization-type "NONE"

awslocal apigateway put-integration \
  --rest-api-id "$API_ID" \
  --resource-id "$PROXY_ID" \
  --http-method ANY \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:mockbank-lambda/invocations

awslocal apigateway create-deployment \
  --rest-api-id "$API_ID" \
  --stage-name local

echo "API Gateway ready at:"
echo "http://localhost:4566/restapis/$API_ID/local/_user_request_"
echo "http://localstack:4566/restapis/$API_ID/local/_user_request_" > /shared/mockbank_url.txt