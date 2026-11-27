SELECT u.id, u.uid
FROM {{ .Ident .UserTable }} as u
WHERE u.uid = {{ .Arg .Query.UserUID }}
{{ if .Query.IsServiceAccount }}
  AND u.is_service_account
{{ else }}
  AND NOT u.is_service_account
{{ end }}
