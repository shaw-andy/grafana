UPDATE "test_schema"."user"
SET
  password = 'new-hash'
WHERE id = 42
  AND salt = 'salt'
  AND password = 'current-hash'
  AND is_service_account = FALSE
