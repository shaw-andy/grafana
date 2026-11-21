UPDATE {{ .Ident .UserTable }}
SET
  password = {{ .Arg .NewPassword }}
WHERE id = {{ .Arg .UserID }}
  AND salt = {{ .Arg .Salt }}
  AND password = {{ .Arg .CurrentPassword }}
  AND is_service_account = FALSE
