package sqlstore

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
	"github.com/grafana/grafana/pkg/setting"
)

// mysqlServer is one MySQL server a Grafana dev or test compose file starts.
// Password values from those files are never stored here.
type mysqlServer struct {
	name              string
	version           string
	command           []string
	publishes3306     bool
	rootPasswordSet   bool
	databaseType      string
	databaseHost      string
	databaseName      string
	databaseUser      string
	databasePassword  bool
	dockerfileDefault string
}

func TestMySQLDevEnvironmentsAreOutsideInnoDBAdvisory(t *testing.T) {
	root := grafanaRepoRoot(t)
	servers := mysqlServersFromDevEnv(t, root)
	require.NotEmpty(t, servers)

	for _, server := range servers {
		t.Run(server.name, func(t *testing.T) {
			require.True(t, server.publishes3306, "compose does not publish the MySQL port")
			require.True(t, server.rootPasswordSet, "MYSQL_ROOT_PASSWORD is unset")
			require.NotContains(t, strings.Join(server.command, " "), "--default-storage-engine")
			require.Equal(t, "mysqld", server.command[0])

			if server.databaseType != "" {
				assertGrafanaMySQLUsesInnoDB(t, root, server)
			}

			if mysqlInnoDBAdvisoryAffected(server.version) {
				t.Errorf("mysql %s is inside the affected range 8.0.40 and prior, 8.4.3 and prior, and 9.1.0 and prior", server.version)
			}
			if server.dockerfileDefault != "" && mysqlInnoDBAdvisoryAffected(server.dockerfileDefault) {
				t.Errorf("Dockerfile ARG mysql_version default %s is inside the affected range", server.dockerfileDefault)
			}
		})
	}
}

func TestMySQLIntegrationWorkflowOverrideIsOutsideInnoDBAdvisory(t *testing.T) {
	root := grafanaRepoRoot(t)
	workflow := filepath.Join(root, ".github/workflows/pr-test-integration.yml")
	text := readText(t, workflow)
	const override = "mysql_version=8.0.43"
	require.Contains(t, text, "make devenv sources=mysql_tests "+override)

	// GNU make exports a command-line variable into the recipe environment,
	// and Compose lets that environment replace the block .env value.
	servers := mysqlServersFromDevEnvWithEnv(t, root, map[string]string{"mysql_version": "8.0.43"})
	var tests *mysqlServer
	for i := range servers {
		if servers[i].name == "mysql_tests" {
			tests = &servers[i]
		}
	}
	require.NotNil(t, tests)
	require.Equal(t, "8.0.43", tests.version)
	require.False(t, mysqlInnoDBAdvisoryAffected(tests.version))
}

func TestMySQLInnoDBAdvisoryVersionBoundaries(t *testing.T) {
	affected := []string{"8.0.0", "8.0.32", "8.0.40", "8.1.0", "8.3.0", "8.4.0", "8.4.3", "9.0.0", "9.0.1", "9.1.0"}
	fixed := []string{"8.0.41", "8.0.43", "8.4.4", "8.4.13", "9.2.0", "9.7.4"}
	for _, version := range affected {
		require.Truef(t, mysqlInnoDBAdvisoryAffected(version), "%s should be affected", version)
	}
	for _, version := range fixed {
		require.Falsef(t, mysqlInnoDBAdvisoryAffected(version), "%s should be outside the affected range", version)
	}
}

func assertGrafanaMySQLUsesInnoDB(t *testing.T, root string, server mysqlServer) {
	t.Helper()
	t.Setenv("GF_DATABASE_TYPE", server.databaseType)
	t.Setenv("GF_DATABASE_HOST", server.databaseHost)
	t.Setenv("GF_DATABASE_NAME", server.databaseName)
	t.Setenv("GF_DATABASE_USER", server.databaseUser)
	// The compose files carry a password. The test uses its own placeholder.
	if server.databasePassword {
		t.Setenv("GF_DATABASE_PASSWORD", "placeholder")
	}

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: root}))
	dbCfg, err := NewDatabaseConfig(cfg, nil)
	require.NoError(t, err)
	require.Equal(t, migrator.MySQL, dbCfg.Type)
	require.Contains(t, dbCfg.Host, server.databaseHost)

	t.Setenv("GRAFANA_TEST_DB", migrator.MySQL)
	require.Equal(t, migrator.MySQL, getTestDBType())

	sql := migrator.NewAddTableMigration(migrator.Table{
		Name: "migration_log",
		Columns: []*migrator.Column{{
			Name:         "id",
			Type:         migrator.DB_BigInt,
			IsPrimaryKey: true,
			Nullable:     false,
		}},
	}).SQL(migrator.NewMysqlDialect())
	require.Contains(t, sql, "ENGINE=InnoDB")

	if server.name == "mysql_tests" {
		driver, conn := newMySQLConnString(server.databaseName)
		if driver != migrator.MySQL || !strings.Contains(conn, ":3306)/"+server.databaseName) {
			t.Fatal("integration tests do not open MySQL on the published port")
		}
	}
}

func mysqlServersFromDevEnv(t *testing.T, root string) []mysqlServer {
	t.Helper()
	return mysqlServersFromDevEnvWithEnv(t, root, nil)
}

func mysqlServersFromDevEnvWithEnv(t *testing.T, root string, processEnv map[string]string) []mysqlServer {
	t.Helper()
	return []mysqlServer{
		composeMySQL(t, root, "ha_test", "devenv/docker/ha_test/docker-compose.yaml", "", processEnv),
		composeMySQL(t, root, "ha-test-unified-alerting", "devenv/docker/ha-test-unified-alerting/docker-compose.yaml", "devenv/docker/ha-test-unified-alerting/grafana-service.yml", processEnv),
		blockMySQL(t, root, "mysql", processEnv),
		blockMySQL(t, root, "mysql_tests", processEnv),
	}
}

func composeMySQL(t *testing.T, root, name, composePath, extraEnvPath string, processEnv map[string]string) mysqlServer {
	t.Helper()
	services := parseComposeServices(t, filepath.Join(root, composePath))
	db, ok := services["db"]
	require.Truef(t, ok, "%s has no db service", composePath)

	server := mysqlServer{
		name:            name,
		version:         imageVersion(t, db.image, nil),
		command:         db.command,
		publishes3306:   publishesPort(db.ports, 3306),
		rootPasswordSet: db.rootPasswordSet,
	}
	if server.command == nil {
		server.command = []string{"mysqld"}
	}
	applyDatabaseEnv(t, &server, db.databaseEnv)
	if extraEnvPath != "" {
		extra := parseComposeServices(t, filepath.Join(root, extraEnvPath))
		grafana, ok := extra["grafana"]
		require.True(t, ok)
		applyDatabaseEnv(t, &server, grafana.databaseEnv)
	}
	return server
}

func blockMySQL(t *testing.T, root, block string, processEnv map[string]string) mysqlServer {
	t.Helper()
	envPath := filepath.Join(root, "devenv/docker/blocks", block, ".env")
	fileEnv := parseDotEnv(t, envPath)
	version := processEnv["mysql_version"]
	if version == "" {
		version = fileEnv["mysql_version"]
	}
	if version == "" {
		version = dockerfileArgDefault(t, filepath.Join(root, "devenv/docker/blocks", block, "Dockerfile"), "mysql_version")
	}

	services := parseComposeServices(t, filepath.Join(root, "devenv/docker/blocks", block, "docker-compose.yaml"))
	var db composeService
	for _, service := range services {
		if service.image != "" || service.buildArg != "" {
			db = service
			break
		}
	}
	require.NotEmpty(t, version)

	server := mysqlServer{
		name:            block,
		version:         version,
		command:         db.command,
		publishes3306:   publishesPort(db.ports, 3306),
		rootPasswordSet: db.rootPasswordSet,
	}
	if server.command == nil {
		server.command = []string{"mysqld"}
	}
	if block == "mysql" {
		server.databaseType = iniValue(t, filepath.Join(root, "devenv/docker/blocks/mysql/config"), "DB_TYPE")
		server.databaseName = "grafana"
		server.databaseHost = "127.0.0.1:3306"
		server.databaseUser = "grafana"
		server.databasePassword = true
	}
	if block == "mysql_tests" {
		server.databaseType = migrator.MySQL
		server.databaseHost = "127.0.0.1:3306"
		server.databaseName = "grafana_tests"
		server.databaseUser = "grafana"
		server.databasePassword = true
		server.dockerfileDefault = dockerfileArgDefault(t, filepath.Join(root, "devenv/docker/blocks/mysql_tests/Dockerfile"), "mysql_version")
	}
	return server
}

func imageVersion(t *testing.T, image string, env map[string]string) string {
	t.Helper()
	if strings.Contains(image, "${mysql_version}") {
		version := env["mysql_version"]
		require.NotEmpty(t, version)
		return version
	}
	parts := strings.Split(image, ":")
	require.GreaterOrEqualf(t, len(parts), 2, "image %q has no tag", image)
	tag := parts[len(parts)-1]
	version, _, _ := strings.Cut(tag, "-")
	return version
}

type composeService struct {
	image           string
	buildArg        string
	command         []string
	ports           []string
	rootPasswordSet bool
	databaseEnv     map[string]string
}

func parseComposeServices(t *testing.T, path string) map[string]composeService {
	t.Helper()
	data := readText(t, path)
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(data), &doc))
	root := doc.Content[0]
	services := mapChild(root, "services")
	if services == nil {
		// A fragment such as grafana-service.yml starts at the services map.
		services = root
	}
	out := map[string]composeService{}
	for i := 0; i+1 < len(services.Content); i += 2 {
		name := services.Content[i].Value
		body := services.Content[i+1]
		out[name] = composeService{
			image:           scalarChild(body, "image"),
			buildArg:        buildArg(body, "mysql_version"),
			command:         stringList(mapChild(body, "command")),
			ports:           stringList(mapChild(body, "ports")),
			rootPasswordSet: envFlag(body, "MYSQL_ROOT_PASSWORD"),
			databaseEnv:     databaseEnv(body),
		}
	}
	return out
}

func databaseEnv(service *yaml.Node) map[string]string {
	env := mapChild(service, "environment")
	if env == nil {
		return nil
	}
	allow := map[string]struct{}{
		"GF_DATABASE_TYPE": {},
		"GF_DATABASE_HOST": {},
		"GF_DATABASE_NAME": {},
		"GF_DATABASE_USER": {},
	}
	out := map[string]string{}
	if env.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(env.Content); i += 2 {
			key := env.Content[i].Value
			if _, ok := allow[key]; ok {
				out[key] = env.Content[i+1].Value
			}
		}
		return out
	}
	for _, item := range env.Content {
		key, value, ok := strings.Cut(item.Value, "=")
		if !ok {
			continue
		}
		if _, allowed := allow[key]; allowed {
			out[key] = value
		}
	}
	return out
}

func envFlag(service *yaml.Node, key string) bool {
	env := mapChild(service, "environment")
	if env == nil {
		return false
	}
	if env.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(env.Content); i += 2 {
			if env.Content[i].Value == key && env.Content[i+1].Value != "" {
				return true
			}
		}
		return false
	}
	prefix := key + "="
	for _, item := range env.Content {
		if strings.HasPrefix(item.Value, prefix) && len(item.Value) > len(prefix) {
			return true
		}
	}
	return false
}

func applyDatabaseEnv(t *testing.T, server *mysqlServer, env map[string]string) {
	t.Helper()
	if env["GF_DATABASE_TYPE"] != "" {
		server.databaseType = env["GF_DATABASE_TYPE"]
	}
	if env["GF_DATABASE_HOST"] != "" {
		server.databaseHost = env["GF_DATABASE_HOST"]
	}
	if env["GF_DATABASE_NAME"] != "" {
		server.databaseName = env["GF_DATABASE_NAME"]
	}
	if env["GF_DATABASE_USER"] != "" {
		server.databaseUser = env["GF_DATABASE_USER"]
	}
	server.databasePassword = true
}

func buildArg(service *yaml.Node, name string) string {
	build := mapChild(service, "build")
	if build == nil {
		return ""
	}
	args := mapChild(build, "args")
	if args == nil {
		return ""
	}
	prefix := name + "="
	for _, item := range args.Content {
		if strings.HasPrefix(item.Value, prefix) {
			return strings.TrimPrefix(item.Value, prefix)
		}
	}
	return ""
}

func mapChild(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarChild(node *yaml.Node, key string) string {
	child := mapChild(node, key)
	if child == nil || child.Kind != yaml.ScalarNode {
		return ""
	}
	return child.Value
}

func stringList(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		return []string{node.Value}
	}
	out := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		out = append(out, item.Value)
	}
	return out
}

func publishesPort(ports []string, want int) bool {
	needle := strconv.Itoa(want)
	for _, port := range ports {
		fields := strings.FieldsFunc(port, func(r rune) bool { return r == ':' || r == '/' })
		for _, field := range fields {
			if field == needle {
				return true
			}
		}
	}
	return false
}

func parseDotEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	out := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.Contains(strings.ToLower(key), "password") || strings.Contains(strings.ToLower(key), "secret") {
			continue
		}
		out[key] = value
	}
	require.NoError(t, scanner.Err())
	return out
}

func dockerfileArgDefault(t *testing.T, path, name string) string {
	t.Helper()
	prefix := "ARG " + name + "="
	for _, line := range strings.Split(readText(t, path), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

func iniValue(t *testing.T, path, key string) string {
	t.Helper()
	prefix := key + " = "
	for _, line := range strings.Split(readText(t, path), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func grafanaRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

// mysqlInnoDBAdvisoryAffected reports whether version is in the MySQL Server
// InnoDB ranges fixed after 8.0.40, 8.4.3, and 9.1.0.
func mysqlInnoDBAdvisoryAffected(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 3 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	switch {
	case major == 8 && minor == 0:
		return patch <= 40
	case major == 8 && minor < 4:
		return true
	case major == 8 && minor == 4:
		return patch <= 3
	case major == 9:
		if minor < 1 {
			return true
		}
		return minor == 1 && patch <= 0
	default:
		return false
	}
}
