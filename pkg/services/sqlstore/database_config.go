package sqlstore

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"

	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

type DatabaseConfig struct {
	Type                        string
	Host                        string
	Name                        string
	User                        string
	Pwd                         string
	Path                        string
	SslMode                     string
	InsecureAllowCleartext      bool
	SSLSNI                      string
	CaCertPath                  string
	ClientKeyPath               string
	ClientCertPath              string
	ServerCertName              string
	ConnectionString            string
	IsolationLevel              string
	MaxOpenConn                 int
	MaxIdleConn                 int
	ConnMaxLifetime             int
	CacheMode                   string
	WALEnabled                  bool
	UrlQueryParams              map[string][]string
	SkipMigrations              bool
	EnsureDefaultOrgAndUser     bool
	MigrationLock               bool
	MigrationLockAttemptTimeout int
	LogQueries                  bool
	DeleteAutoGenIDs            bool
	// SQLite only
	QueryRetries int
	// SQLite only
	TransactionRetries int
}

func NewDatabaseConfig(cfg *setting.Cfg, features featuremgmt.FeatureToggles) (*DatabaseConfig, error) {
	if cfg == nil {
		return nil, errors.New("cfg cannot be nil")
	}

	dbCfg := &DatabaseConfig{}
	if err := dbCfg.readConfig(cfg); err != nil {
		return nil, err
	}

	if err := dbCfg.buildConnectionString(cfg, features); err != nil {
		return nil, err
	}

	return dbCfg, nil
}

func (dbCfg *DatabaseConfig) readConfig(cfg *setting.Cfg) error {
	sec := cfg.Raw.Section("database")

	cfgURL := sec.Key("url").String()
	if len(cfgURL) != 0 {
		dbURL, err := url.Parse(cfgURL)
		if err != nil {
			return err
		}
		dbCfg.Type = dbURL.Scheme
		dbCfg.Host = dbURL.Host

		pathSplit := strings.Split(dbURL.Path, "/")
		if len(pathSplit) > 1 {
			dbCfg.Name = pathSplit[1]
		}

		userInfo := dbURL.User
		if userInfo != nil {
			dbCfg.User = userInfo.Username()
			dbCfg.Pwd, _ = userInfo.Password()
		}

		dbCfg.UrlQueryParams = dbURL.Query()
	} else {
		dbCfg.Type = sec.Key("type").String()
		dbCfg.Host = sec.Key("host").String()
		if port := sec.Key("port").String(); port != "" {
			dbCfg.Host = dbCfg.Host + ":" + port
		}
		dbCfg.Name = sec.Key("name").String()
		dbCfg.User = sec.Key("user").String()
		dbCfg.ConnectionString = sec.Key("connection_string").String()
		dbCfg.Pwd = sec.Key("password").String()
	}

	dbCfg.MaxOpenConn = sec.Key("max_open_conn").MustInt(0)
	dbCfg.MaxIdleConn = sec.Key("max_idle_conn").MustInt(2)
	dbCfg.ConnMaxLifetime = sec.Key("conn_max_lifetime").MustInt(14400)

	dbCfg.SslMode = sec.Key("ssl_mode").String()
	dbCfg.InsecureAllowCleartext = sec.Key("insecure_allow_cleartext").MustBool(false)
	dbCfg.SSLSNI = sec.Key("ssl_sni").String()
	dbCfg.CaCertPath = sec.Key("ca_cert_path").String()
	dbCfg.ClientKeyPath = sec.Key("client_key_path").String()
	dbCfg.ClientCertPath = sec.Key("client_cert_path").String()
	dbCfg.ServerCertName = sec.Key("server_cert_name").String()
	dbCfg.Path = sec.Key("path").MustString("data/grafana.db")
	dbCfg.IsolationLevel = sec.Key("isolation_level").String()

	dbCfg.CacheMode = sec.Key("cache_mode").MustString("private")
	dbCfg.WALEnabled = sec.Key("wal").MustBool(false)
	dbCfg.SkipMigrations = sec.Key("skip_migrations").MustBool()
	dbCfg.EnsureDefaultOrgAndUser = sec.Key("ensure_default_org_and_user").MustBool(true)
	dbCfg.MigrationLock = sec.Key("migration_locking").MustBool(true)
	dbCfg.MigrationLockAttemptTimeout = sec.Key("locking_attempt_timeout_sec").MustInt()

	dbCfg.QueryRetries = sec.Key("query_retries").MustInt()
	dbCfg.TransactionRetries = sec.Key("transaction_retries").MustInt(10)

	dbCfg.LogQueries = sec.Key("log_queries").MustBool(false)
	dbCfg.DeleteAutoGenIDs = sec.Key("delete_auto_gen_ids").MustBool(false)

	return nil
}

func (dbCfg *DatabaseConfig) buildConnectionString(cfg *setting.Cfg, features featuremgmt.FeatureToggles) error {
	if dbCfg.ConnectionString != "" {
		return dbCfg.requireEncryptedTransport()
	}

	cnnstr := ""

	switch dbCfg.Type {
	case migrator.MySQL:
		protocol := "tcp"
		if strings.HasPrefix(dbCfg.Host, "/") {
			protocol = "unix"
		}

		switch dbCfg.SslMode {
		case "":
			dbCfg.SslMode = "true"
			if protocol == "unix" {
				dbCfg.SslMode = "false"
			}
		case "true", "skip-verify", "false":
		default:
			return fmt.Errorf(`invalid ssl_mode %q for mysql: use "true", "skip-verify" or "false"`, dbCfg.SslMode)
		}

		cnnstr = fmt.Sprintf("%s:%s@%s(%s)/%s?collation=utf8mb4_unicode_ci&allowNativePasswords=true&clientFoundRows=true&parseTime=true",
			dbCfg.User, dbCfg.Pwd, protocol, dbCfg.Host, dbCfg.Name)

		if dbCfg.SslMode == "true" || dbCfg.SslMode == "skip-verify" {
			tlsCert, err := makeCert(dbCfg)
			if err != nil {
				return err
			}
			if err := mysql.RegisterTLSConfig("custom", tlsCert); err != nil {
				return err
			}

			cnnstr += "&tls=custom"
		}

		if isolation := dbCfg.IsolationLevel; isolation != "" {
			val := url.QueryEscape(fmt.Sprintf("'%s'", isolation))
			cnnstr += fmt.Sprintf("&transaction_isolation=%s", val)
		}

		cnnstr += "&sql_mode=ANSI_QUOTES"
		cnnstr += buildExtraConnectionString('&', dbCfg.UrlQueryParams)
	case migrator.Postgres:
		addr, err := util.SplitHostPortDefault(dbCfg.Host, "127.0.0.1", "5432")
		if err != nil {
			return fmt.Errorf("invalid host specifier '%s': %w", dbCfg.Host, err)
		}

		if dbCfg.SslMode == "" {
			dbCfg.SslMode = string(pq.SSLModeVerifyFull)
		}

		args := []any{dbCfg.User, addr.Host, addr.Port, dbCfg.Name, dbCfg.SslMode, dbCfg.ClientCertPath,
			dbCfg.ClientKeyPath, dbCfg.CaCertPath}

		for i, arg := range args {
			if arg == "" {
				args[i] = "''"
			}
		}
		cnnstr = fmt.Sprintf("user=%s host=%s port=%s dbname=%s sslmode=%s sslcert=%s sslkey=%s sslrootcert=%s", args...)
		if dbCfg.SSLSNI != "" {
			cnnstr += fmt.Sprintf(" sslsni=%s", dbCfg.SSLSNI)
		}
		if dbCfg.Pwd != "" {
			cnnstr += fmt.Sprintf(" password=%s", dbCfg.Pwd)
		}

		cnnstr += buildExtraConnectionString(' ', dbCfg.UrlQueryParams)
	case migrator.SQLite:
		// special case for tests
		if !filepath.IsAbs(dbCfg.Path) {
			dbCfg.Path = filepath.Join(cfg.DataPath, dbCfg.Path)
		}
		if err := os.MkdirAll(path.Dir(dbCfg.Path), 0o750); err != nil {
			return err
		}

		cnnstr = fmt.Sprintf("file:%s?cache=%s&mode=rwc", dbCfg.Path, dbCfg.CacheMode)

		// SQLite keeps the journal mode in the database file, so a database that was once
		// opened with WAL stays in WAL until we ask for something else.
		if dbCfg.WALEnabled {
			cnnstr += "&_journal_mode=WAL"
		} else {
			cnnstr += "&_journal_mode=DELETE"
		}

		cnnstr += buildExtraConnectionString('&', dbCfg.UrlQueryParams)
	default:
		return fmt.Errorf("unknown database type: %s", dbCfg.Type)
	}

	dbCfg.ConnectionString = cnnstr

	return dbCfg.requireEncryptedTransport()
}

var errCleartextDatabaseConnection = errors.New("database connection would not be encrypted: enable TLS in the ssl mode setting, " +
	"or set insecure_allow_cleartext = true to accept credentials and queries being readable on the network")

func (dbCfg *DatabaseConfig) requireEncryptedTransport() error {
	if dbCfg.InsecureAllowCleartext {
		return nil
	}
	switch dbCfg.Type {
	case migrator.MySQL:
		return requireMySQLTLS(dbCfg.ConnectionString)
	case migrator.Postgres:
		return RequirePostgresTLS(dbCfg.ConnectionString)
	}
	return nil
}

func requireMySQLTLS(connStr string) error {
	myCfg, err := mysql.ParseDSN(connStr)
	if err != nil {
		return fmt.Errorf("invalid mysql connection string: %w", err)
	}
	if myCfg.Net == "unix" {
		return nil
	}
	if myCfg.TLS == nil || myCfg.AllowFallbackToPlaintext {
		return errCleartextDatabaseConnection
	}
	return nil
}

// RequirePostgresTLS returns an error when connStr lets a session to a network host run without TLS.
// An unset sslmode is refused as well: lib/pq treats it as require, but pgx, which OpenFGA uses to
// open the same string, treats it as prefer and falls back to cleartext.
func RequirePostgresTLS(connStr string) error {
	pgCfg, err := pq.NewConfig(connStr)
	if err != nil {
		return fmt.Errorf("invalid postgres connection string: %w", err)
	}
	switch pgCfg.SSLMode {
	case pq.SSLModeRequire, pq.SSLModeVerifyCA, pq.SSLModeVerifyFull:
		return nil
	}
	if postgresUnixSocketsOnly(pgCfg) {
		return nil
	}
	return fmt.Errorf("%w (sslmode %q)", errCleartextDatabaseConnection, pgCfg.SSLMode)
}

func postgresUnixSocketsOnly(pgCfg pq.Config) bool {
	isUnix := func(host string, hostaddr netip.Addr) bool {
		return hostaddr == (netip.Addr{}) && (filepath.IsAbs(host) || strings.HasPrefix(host, "@"))
	}
	if !isUnix(pgCfg.Host, pgCfg.Hostaddr) {
		return false
	}
	for _, m := range pgCfg.Multi {
		if !isUnix(m.Host, m.Hostaddr) {
			return false
		}
	}
	return true
}

func buildExtraConnectionString(sep rune, urlQueryParams map[string][]string) string {
	if urlQueryParams == nil {
		return ""
	}

	var sb strings.Builder
	for key, values := range urlQueryParams {
		for _, value := range values {
			sb.WriteRune(sep)
			sb.WriteString(key)
			sb.WriteRune('=')
			sb.WriteString(value)
		}
	}
	return sb.String()
}
