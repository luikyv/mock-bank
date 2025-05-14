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
);

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
  '92792126019929279212650822221989319252576',
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
);
