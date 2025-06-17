INSERT INTO oauth_clients (
  id,
  data,
  org_id,
  created_at,
  updated_at
) VALUES (
  'client_one',
  '{
    "client_id": "client_one",
    "redirect_uris": ["https://localhost.emobix.co.uk:8443/test/a/mockbank/callback"],
    "grant_types": ["authorization_code", "client_credentials", "implicit", "refresh_token"],
    "response_types": ["code id_token"],
    "jwks_uri": "https://keystore.local/00000000-0000-0000-0000-000000000000/11111111-1111-1111-1111-111111111111/application.jwks",
    "scope": "openid consents consent resources accounts payments recurring-payments recurring-consent",
    "id_token_encrypted_response_alg": "RSA-OAEP",
    "id_token_encrypted_response_enc": "A256GCM",
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "PS256",
    "custom_attributes": {"org_id":"00000000-0000-0000-0000-000000000000"},
    "hashed_registration_token": "hashed_token"
  }'::jsonb,
  '00000000-0000-0000-0000-000000000000',
  now(),
  now()
)
ON CONFLICT (id) DO UPDATE SET
  data = EXCLUDED.data,
  org_id = EXCLUDED.org_id,
  updated_at = now();

INSERT INTO mock_users (
  id,
  username,
  name,
  cpf,
  org_id,
  created_at,
  updated_at
) VALUES (
  '11111111-1111-1111-1111-111111111111',
  'john',
  'Mr. John',
  '12345678901',
  '00000000-0000-0000-0000-000000000000',
  now(),
  now()
)
ON CONFLICT (id) DO UPDATE SET
  username = EXCLUDED.username,
  name = EXCLUDED.name,
  cpf = EXCLUDED.cpf,
  org_id = EXCLUDED.org_id,
  updated_at = now();


INSERT INTO accounts (
  id,
  user_id,
  number,
  type,
  subtype,
  available_amount,
  blocked_amount,
  automatically_invested_amount,
  overdraft_limit_contracted,
  overdraft_limit_used,
  overdraft_limit_unarranged,
  org_id,
  created_at,
  updated_at
) VALUES (
  '11111111-1111-1111-1111-111111111111',
  '11111111-1111-1111-1111-111111111111',
  '94088392',
  'CONTA_DEPOSITO_A_VISTA',
  'INDIVIDUAL',
  '1000.00',
  '0.00',
  '0.00',
  NULL,
  NULL,
  NULL,
  '00000000-0000-0000-0000-000000000000',
  now(),
  now()
)
ON CONFLICT (id) DO UPDATE SET
  user_id = EXCLUDED.user_id,
  number = EXCLUDED.number,
  type = EXCLUDED.type,
  subtype = EXCLUDED.subtype,
  available_amount = EXCLUDED.available_amount,
  blocked_amount = EXCLUDED.blocked_amount,
  automatically_invested_amount = EXCLUDED.automatically_invested_amount,
  overdraft_limit_contracted = EXCLUDED.overdraft_limit_contracted,
  overdraft_limit_used = EXCLUDED.overdraft_limit_used,
  overdraft_limit_unarranged = EXCLUDED.overdraft_limit_unarranged,
  org_id = EXCLUDED.org_id,
  updated_at = now();

