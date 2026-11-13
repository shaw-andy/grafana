package sqlstore

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/grafana/grafana/pkg/util/xorm"
)

// TestMySQLServerPinsOutsideAffectedDMLRange starts every MySQL server the
// repository actually launches and runs INSERT, UPDATE, and DELETE through the
// same connection helper the integration tests use. It fails while a launched
// server reports a version inside the ranges affected by the Server: DML
// vulnerability fixed in MySQL 8.0.44, 8.4.7, and the 9.4 line after 9.4.0.
func TestMySQLServerPinsOutsideAffectedDMLRange(t *testing.T) {
	for _, tc := range []struct {
		version  string
		affected bool
	}{
		{version: "8.0.0", affected: true},
		{version: "8.0.32", affected: true},
		{version: "8.0.43", affected: true},
		{version: "8.0.44", affected: false},
		{version: "8.4.0", affected: true},
		{version: "8.4.6", affected: true},
		{version: "8.4.7", affected: false},
		{version: "9.0.0", affected: true},
		{version: "9.4.0", affected: true},
		{version: "9.4.1", affected: false},
		{version: "5.7.44", affected: false},
	} {
		got, err := mysqlVersionAffected(tc.version)
		if err != nil {
			t.Fatalf("mysqlVersionAffected(%s): %v", tc.version, err)
		}
		if got != tc.affected {
			t.Fatalf("mysqlVersionAffected(%s) = %v, want %v", tc.version, got, tc.affected)
		}
	}

	root := grafanaRepoRoot(t)
	pins := groupMySQLServerPins(discoverMySQLServerPins(t, root))
	if len(pins) == 0 {
		t.Fatal("found no MySQL server pins to launch")
	}

	for _, pin := range pins {
		pin := pin
		t.Run(pin.Name, func(t *testing.T) {
			host, port, cleanup := pin.launch(t, root)
			t.Cleanup(cleanup)
			reported := exerciseMySQLDML(t, host, port, pin.service)
			if reported != pin.Version {
				t.Fatalf("server launched from %s reported %s, want pin %s", pin.origins(), reported, pin.Version)
			}
			affected, err := mysqlVersionAffected(reported)
			if err != nil {
				t.Fatalf("reported version %q: %v", reported, err)
			}
			if affected {
				t.Errorf("MySQL %s launched from %s accepted INSERT, UPDATE, and DELETE from a high-privilege TCP account while its version is inside the affected Server: DML ranges (8.0.0-8.0.43, 8.4.0-8.4.6, 9.0.0-9.4.0)", reported, pin.origins())
			}
		})
	}
}

type mysqlServerPin struct {
	Name    string
	Version string
	Kind    string // make, dockerfile, image
	Origins []string
	File    string
	Image   string
	service mysqlServiceConfig
}

func (p mysqlServerPin) launchKey() string {
	return p.Kind + "\x00" + p.Version + "\x00" + p.Image + "\x00" + p.File
}

func (p mysqlServerPin) origins() string {
	return strings.Join(p.Origins, ", ")
}

func groupMySQLServerPins(pins []mysqlServerPin) []mysqlServerPin {
	grouped := make([]mysqlServerPin, 0, len(pins))
	index := map[string]int{}
	for _, pin := range pins {
		key := pin.launchKey()
		if i, ok := index[key]; ok {
			grouped[i].Origins = append(grouped[i].Origins, pin.Origins...)
			continue
		}
		index[key] = len(grouped)
		grouped = append(grouped, pin)
	}
	return grouped
}

func (p mysqlServerPin) launch(t *testing.T, root string) (host, port string, cleanup func()) {
	t.Helper()
	switch p.Kind {
	case "make":
		return launchMakeDevenvMySQL(t, root, p.Version, p.service.RootPassword)
	case "dockerfile":
		return launchDockerfileMySQL(t, root, p.File, p.service, false, "")
	case "image":
		return launchImageMySQL(t, p.Image, p.service)
	default:
		t.Fatalf("unknown pin kind %q", p.Kind)
		return "", "", func() {}
	}
}

type mysqlServiceConfig struct {
	RootPassword string
	Database     string
	Command      []string
	TmpfsData    bool
	Env          map[string]string
}

func discoverMySQLServerPins(t *testing.T, root string) []mysqlServerPin {
	t.Helper()
	var pins []mysqlServerPin
	makeRe := regexp.MustCompile(`make devenv sources=mysql_tests mysql_version=(\d+\.\d+\.\d+)`)
	imageRe := regexp.MustCompile(`image:\s*["']?mysql:(\d+\.\d+\.\d+)["']?`)
	argRe := regexp.MustCompile(`^ARG mysql_version=(\d+\.\d+\.\d+)\s*$`)
	fromRe := regexp.MustCompile(`(?m)^FROM mysql:\$\{mysql_version\}\s*$`)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "public" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == filepath.Join("devenv", "docker-compose.yaml") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := string(data)

		if strings.HasSuffix(path, "Dockerfile") && fromRe.MatchString(text) {
			version := ""
			lineNo := 0
			sc := bufio.NewScanner(bytes.NewReader(data))
			for n := 1; sc.Scan(); n++ {
				if m := argRe.FindStringSubmatch(sc.Text()); m != nil {
					version = m[1]
					lineNo = n
				}
			}
			if version == "" {
				t.Fatalf("%s uses FROM mysql:${mysql_version} without a default ARG", rel)
			}
			svc := mustMySQLService(t, filepath.Join(root, "devenv", "docker", "blocks", "mysql_tests", "docker-compose.yaml"), "")
			pins = append(pins, mysqlServerPin{
				Name:    "dockerfile-default-" + version,
				Version: version,
				Kind:    "dockerfile",
				Origins: []string{fmt.Sprintf("%s:%d", rel, lineNo)},
				File:    path,
				service: svc,
			})
		}

		sc := bufio.NewScanner(bytes.NewReader(data))
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			if m := makeRe.FindStringSubmatch(line); m != nil {
				origin := fmt.Sprintf("%s:%d", rel, n)
				pins = append(pins, mysqlServerPin{
					Name:    "make-devenv-" + m[1] + "-" + strings.ReplaceAll(origin, "/", "_"),
					Version: m[1],
					Kind:    "make",
					Origins: []string{origin},
					service: mustMySQLService(t, filepath.Join(root, "devenv", "docker", "blocks", "mysql_tests", "docker-compose.yaml"), ""),
				})
			}
			if m := imageRe.FindStringSubmatch(line); m != nil {
				origin := fmt.Sprintf("%s:%d", rel, n)
				image := "mysql:" + m[1]
				pins = append(pins, mysqlServerPin{
					Name:    "image-" + m[1] + "-" + strings.ReplaceAll(origin, "/", "_"),
					Version: m[1],
					Kind:    "image",
					Origins: []string{origin},
					Image:   image,
					File:    path,
					service: mustMySQLService(t, path, image),
				})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}

	var workflowPins int
	for _, pin := range pins {
		if pin.Kind == "make" {
			workflowPins++
		}
	}
	if workflowPins < 2 {
		t.Fatalf("expected both integration workflow jobs to start mysql_tests, found %d", workflowPins)
	}
	return pins
}

func mustMySQLService(t *testing.T, path, image string) mysqlServiceConfig {
	t.Helper()
	svc, err := loadMySQLService(path, image)
	if err != nil {
		t.Fatalf("load MySQL service from %s: %v", path, err)
	}
	if svc.RootPassword == "" {
		t.Fatalf("%s does not set MYSQL_ROOT_PASSWORD for %s", path, image)
	}
	if svc.Database == "" {
		t.Fatalf("%s does not set MYSQL_DATABASE for %s", path, image)
	}
	if len(svc.Command) == 0 {
		svc.Command = []string{"mysqld"}
	}
	return svc
}

func loadMySQLService(path, image string) (mysqlServiceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mysqlServiceConfig{}, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return mysqlServiceConfig{}, err
	}
	services, _ := doc["services"].(map[string]any)
	if services == nil {
		services = doc
	}
	for _, raw := range services {
		svc, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		img, _ := svc["image"].(string)
		if image != "" && img != image {
			continue
		}
		if image == "" {
			if _, hasBuild := svc["build"]; !hasBuild && img == "" {
				continue
			}
		}
		env := mapEnv(svc["environment"])
		cfg := mysqlServiceConfig{
			RootPassword: env["MYSQL_ROOT_PASSWORD"],
			Database:     env["MYSQL_DATABASE"],
			Command:      stringList(svc["command"]),
			Env:          env,
		}
		if _, ok := svc["tmpfs"]; ok {
			cfg.TmpfsData = true
		}
		return cfg, nil
	}
	return mysqlServiceConfig{}, fmt.Errorf("no mysql service in %s", path)
}

func mapEnv(raw any) map[string]string {
	out := map[string]string{}
	switch env := raw.(type) {
	case map[string]any:
		for k, v := range env {
			out[k] = fmt.Sprint(v)
		}
	case []any:
		for _, item := range env {
			parts := strings.SplitN(fmt.Sprint(item), "=", 2)
			if len(parts) == 2 {
				out[parts[0]] = parts[1]
			}
		}
	}
	return out
}

func stringList(raw any) []string {
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		return strings.Fields(v)
	default:
		return nil
	}
}

func launchMakeDevenvMySQL(t *testing.T, root, version, secret string) (string, string, func()) {
	t.Helper()
	devenvDir := filepath.Join(root, "devenv")
	existed := map[string]bool{}
	for _, name := range []string{"docker-compose.yaml", "conf.tmp", ".env"} {
		_, err := os.Stat(filepath.Join(devenvDir, name))
		existed[name] = err == nil
	}
	cleanup := func() {
		cmd := exec.Command("make", "devenv-down", "sources=mysql_tests")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("devenv-down: %v\n%s", err, redactMySQLSecrets(string(out), secret))
		}
		for _, name := range []string{"docker-compose.yaml", "conf.tmp", ".env"} {
			if !existed[name] {
				_ = os.Remove(filepath.Join(devenvDir, name))
			}
		}
	}
	cmd := exec.Command("make", "devenv", "sources=mysql_tests", "mysql_version="+version)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		cleanup()
		t.Fatalf("make devenv mysql_version=%s: %v\n%s", version, err, redactMySQLSecrets(string(out), secret))
	}
	return "127.0.0.1", "3306", cleanup
}

func launchDockerfileMySQL(t *testing.T, root, dockerfile string, svc mysqlServiceConfig, withArg bool, version string) (string, string, func()) {
	t.Helper()
	tag := "grafana-mysql-pin-dockerfile:under-test"
	args := []string{"build", "-t", tag, "-f", dockerfile}
	if withArg {
		args = append(args, "--build-arg", "mysql_version="+version)
	}
	args = append(args, filepath.Dir(dockerfile))
	cmd := exec.Command("docker", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker build %s: %v\n%s", dockerfile, err, redactMySQLSecrets(string(out), svc.RootPassword))
	}
	return launchImageMySQL(t, tag, svc)
}

func launchImageMySQL(t *testing.T, image string, svc mysqlServiceConfig) (string, string, func()) {
	t.Helper()
	name := fmt.Sprintf("grafana-mysql-pin-%d", time.Now().UnixNano())
	args := []string{"run", "-d", "--name", name, "--platform", "linux/amd64"}
	if svc.TmpfsData {
		args = append(args, "--tmpfs", "/var/lib/mysql:rw")
	}
	for key, val := range svc.Env {
		args = append(args, "-e", key+"="+val)
	}
	args = append(args,
		"-p", "127.0.0.1::3306",
		image,
	)
	args = append(args, svc.Command...)
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	cleanup := func() {
		rm := exec.Command("docker", "rm", "-f", name)
		_ = rm.Run()
	}
	if err != nil {
		cleanup()
		t.Fatalf("docker run %s: %v\n%s", image, err, redactMySQLSecrets(string(out), svc.RootPassword))
	}
	port := publishedPort(t, name, svc.RootPassword)
	return "127.0.0.1", port, cleanup
}

func publishedPort(t *testing.T, name, secret string) string {
	t.Helper()
	out, err := exec.Command("docker", "port", name, "3306").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, redactMySQLSecrets(string(out), secret))
	}
	line := strings.TrimSpace(string(out))
	// 127.0.0.1:32768 or 0.0.0.0:32768
	if i := strings.LastIndex(line, ":"); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	t.Fatalf("cannot parse published port %q", line)
	return ""
}

func exerciseMySQLDML(t *testing.T, host, port string, svc mysqlServiceConfig) string {
	t.Helper()
	t.Setenv("MYSQL_HOST", host)
	t.Setenv("MYSQL_PORT", port)
	t.Setenv("MYSQL_USER", "root")
	t.Setenv("MYSQL_PASSWORD", svc.RootPassword)

	driver, conn := newMySQLConnString(svc.Database)
	if driver != "mysql" {
		t.Fatalf("integration helper driver = %s, want mysql", driver)
	}
	if !strings.Contains(conn, "@tcp("+host+":"+port+")/") {
		t.Fatal("integration helper did not build a TCP DSN for the launched server")
	}

	var engine *xorm.Engine
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for {
		engine, lastErr = xorm.NewEngine(driver, conn)
		if lastErr == nil {
			_, lastErr = engine.Exec("SELECT 1")
			if lastErr == nil {
				break
			}
			_ = engine.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("MySQL at %s:%s did not accept a connection: %v", host, port, lastErr)
		}
		time.Sleep(time.Second)
	}
	t.Cleanup(func() { _ = engine.Close() })

	grants, err := engine.SQL("SHOW GRANTS FOR CURRENT_USER()").Query()
	if err != nil {
		t.Fatalf("show grants: %v", err)
	}
	var grantText strings.Builder
	for _, row := range grants {
		for _, val := range row {
			grantText.Write(val)
			grantText.WriteByte('\n')
		}
	}
	if !highPrivilegeGrant(grantText.String()) {
		t.Fatalf("connection is not a high-privilege account, grants: %s", grantText.String())
	}

	statements := []struct {
		sql  string
		want int64
	}{
		{sql: "CREATE TABLE dml_probe (id INT PRIMARY KEY, v VARCHAR(32))", want: -1},
		{sql: "INSERT INTO dml_probe (id, v) VALUES (1, 'inserted')", want: 1},
		{sql: "UPDATE dml_probe SET v = 'updated' WHERE id = 1", want: 1},
	}
	for _, stmt := range statements {
		res, err := engine.Exec(stmt.sql)
		if err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
		if stmt.want >= 0 {
			n, err := res.RowsAffected()
			if err != nil {
				t.Fatalf("rows affected for %s: %v", stmt.sql, err)
			}
			if n != stmt.want {
				t.Fatalf("%s affected %d rows, want %d", stmt.sql, n, stmt.want)
			}
		}
	}
	got, err := scalar(engine, "SELECT v FROM dml_probe WHERE id = 1")
	if err != nil {
		t.Fatalf("read updated row: %v", err)
	}
	if got != "updated" {
		t.Fatalf("UPDATE result = %q, want updated", got)
	}
	res, err := engine.Exec("DELETE FROM dml_probe WHERE id = 1")
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("delete rows affected: %v", err)
	}
	if n != 1 {
		t.Fatalf("DELETE affected %d rows, want 1", n)
	}
	left, err := scalar(engine, "SELECT COUNT(*) FROM dml_probe")
	if err != nil {
		t.Fatalf("count after delete: %v", err)
	}
	if left != "0" {
		t.Fatalf("rows left after DELETE = %s, want 0", left)
	}

	version, err := scalar(engine, "SELECT VERSION()")
	if err != nil {
		t.Fatalf("VERSION(): %v", err)
	}
	numeric := regexp.MustCompile(`\d+\.\d+\.\d+`).FindString(version)
	if numeric == "" {
		t.Fatalf("VERSION() = %q, no numeric version", version)
	}
	return numeric
}

func highPrivilegeGrant(grants string) bool {
	if strings.Contains(grants, "ALL PRIVILEGES ON *.*") {
		return true
	}
	// MySQL 8 expands ALL PRIVILEGES into the individual global privileges.
	return strings.Contains(grants, "INSERT") &&
		strings.Contains(grants, "UPDATE") &&
		strings.Contains(grants, "DELETE") &&
		strings.Contains(grants, "SUPER") &&
		strings.Contains(grants, "ON *.*") &&
		strings.Contains(grants, "WITH GRANT OPTION")
}

func scalar(engine *xorm.Engine, query string) (string, error) {
	rows, err := engine.SQL(query).Query()
	if err != nil {
		return "", err
	}
	if len(rows) != 1 {
		return "", fmt.Errorf("%s returned %d rows", query, len(rows))
	}
	if len(rows[0]) != 1 {
		return "", fmt.Errorf("%s returned %d columns", query, len(rows[0]))
	}
	for _, val := range rows[0] {
		return string(val), nil
	}
	return "", fmt.Errorf("%s returned an empty row", query)
}

func mysqlVersionAffected(version string) (bool, error) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("want major.minor.patch")
	}
	nums := make([]int, 3)
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return false, err
		}
		nums[i] = n
	}
	maj, min, pat := nums[0], nums[1], nums[2]
	switch {
	case maj == 8 && min == 0 && pat <= 43:
		return true, nil
	case maj == 8 && min == 4 && pat <= 6:
		return true, nil
	case maj == 9 && (min < 4 || (min == 4 && pat == 0)):
		return true, nil
	default:
		return false, nil
	}
}

func grafanaRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "devenv", "docker", "blocks", "mysql_tests", "Dockerfile")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("grafana repo root not found")
		}
		dir = parent
	}
}

func redactMySQLSecrets(text, secret string) string {
	if secret != "" {
		text = strings.ReplaceAll(text, secret, "[redacted]")
	}
	return text
}
