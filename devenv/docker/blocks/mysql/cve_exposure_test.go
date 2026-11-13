package mysql

import (
	"bufio"
	"bytes"
	"encoding/json"
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
)

// Affected ranges are the ones Oracle published for the MySQL Server Optimizer
// issue: 8.0.0-8.0.45, 8.4.0-8.4.8, and 9.0.0-9.6.0. These tests fail while a
// devenv or test database is still started from a version inside those ranges.

type mysqlVersion struct {
	major, minor, patch int
	raw                 string
}

func parseMySQLVersion(raw string) (mysqlVersion, error) {
	raw = strings.TrimSpace(raw)
	head := raw
	if i := strings.IndexAny(head, "-+"); i >= 0 {
		head = head[:i]
	}
	parts := strings.Split(head, ".")
	if len(parts) < 3 {
		return mysqlVersion{}, fmt.Errorf("not a MySQL version: %q", raw)
	}
	nums := make([]int, 3)
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return mysqlVersion{}, fmt.Errorf("not a MySQL version: %q", raw)
		}
		nums[i] = n
	}
	return mysqlVersion{major: nums[0], minor: nums[1], patch: nums[2], raw: raw}, nil
}

func (v mysqlVersion) affected() bool {
	switch {
	case v.major == 8 && v.minor == 0 && v.patch <= 45:
		return true
	case v.major == 8 && v.minor == 4 && v.patch <= 8:
		return true
	case v.major == 9 && (v.minor < 6 || (v.minor == 6 && v.patch == 0)):
		return true
	default:
		return false
	}
}

func (v mysqlVersion) String() string { return v.raw }

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s: %v", root, err)
	}
	return root
}

type pin struct {
	source  string
	version mysqlVersion
}

func mustVersion(t *testing.T, source, raw string) mysqlVersion {
	t.Helper()
	v, err := parseMySQLVersion(raw)
	if err != nil {
		t.Fatalf("%s: %v", source, err)
	}
	return v
}

func readEnvValue(t *testing.T, path, key string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	prefix := key + "="
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, prefix) {
			return strings.Trim(strings.TrimPrefix(line, prefix), `"'`)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	t.Fatalf("%s has no %s", path, key)
	return ""
}

var (
	imageTagPattern    = regexp.MustCompile(`(?:image:\s*mysql:|bitnami/mysql:)(\d+\.\d+\.\d+)`)
	workflowPinPattern = regexp.MustCompile(`mysql_version=(\d+\.\d+\.\d+)`)
	dockerArgPattern   = regexp.MustCompile(`(?m)^ARG\s+mysql_version=(\d+\.\d+\.\d+)\s*$`)
)

func collectPins(t *testing.T, root string) []pin {
	t.Helper()
	var pins []pin
	add := func(source, raw string) {
		pins = append(pins, pin{source: source, version: mustVersion(t, source, raw)})
	}

	envFiles := []string{
		"devenv/docker/blocks/mysql/.env",
		"devenv/docker/blocks/mysql_tests/.env",
	}
	for _, rel := range envFiles {
		add(rel, readEnvValue(t, filepath.Join(root, rel), "mysql_version"))
	}

	dockerfile := "devenv/docker/blocks/mysql_tests/Dockerfile"
	body, err := os.ReadFile(filepath.Join(root, dockerfile))
	if err != nil {
		t.Fatal(err)
	}
	m := dockerArgPattern.FindSubmatch(body)
	if m == nil {
		t.Fatalf("%s has no ARG mysql_version default", dockerfile)
	}
	add(dockerfile, string(m[1]))

	composeFiles := []string{
		"devenv/docker/ha_test/docker-compose.yaml",
		"devenv/docker/ha-test-unified-alerting/docker-compose.yaml",
		"pkg/storage/unified/README.md",
	}
	for _, rel := range composeFiles {
		text, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		found := imageTagPattern.FindAllSubmatch(text, -1)
		if len(found) == 0 {
			t.Fatalf("%s declares no pinned mysql image", rel)
		}
		for _, match := range found {
			add(rel, string(match[1]))
		}
	}

	workflow := ".github/workflows/pr-test-integration.yml"
	text, err := os.ReadFile(filepath.Join(root, workflow))
	if err != nil {
		t.Fatal(err)
	}
	found := workflowPinPattern.FindAllSubmatch(text, -1)
	if len(found) == 0 {
		t.Fatalf("%s does not override mysql_version", workflow)
	}
	for _, match := range found {
		add(workflow, string(match[1]))
	}
	return pins
}

func TestMySQLVersionRanges(t *testing.T) {
	cases := []struct {
		raw      string
		affected bool
	}{
		{"8.0.0", true},
		{"8.0.32", true},
		{"8.0.43", true},
		{"8.0.45", true},
		{"8.0.46", false},
		{"8.4.0", true},
		{"8.4.8", true},
		{"8.4.9", false},
		{"9.0.0", true},
		{"9.6.0", true},
		{"9.6.1", false},
		{"9.7.0", false},
	}
	for _, tc := range cases {
		v, err := parseMySQLVersion(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if v.affected() != tc.affected {
			t.Errorf("%s affected=%v, want %v", tc.raw, v.affected(), tc.affected)
		}
	}
}

func TestPinnedMySQLServersAreOutsideOptimizerCVERange(t *testing.T) {
	root := repoRoot(t)
	for _, pin := range collectPins(t, root) {
		if pin.version.affected() {
			t.Errorf("%s starts MySQL %s, which is inside an affected Optimizer range (8.0.0-8.0.45, 8.4.0-8.4.8, 9.0.0-9.6.0)", pin.source, pin.version)
		}
	}

	// The block compose file does not pin a number itself; it interpolates the
	// .env value and publishes the server port. Both have to stay true after a fix.
	compose := filepath.Join(root, "devenv/docker/blocks/mysql/docker-compose.yaml")
	text, err := os.ReadFile(compose)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(text, []byte("image: mysql:${mysql_version}")) {
		t.Errorf("%s no longer starts the image selected by mysql_version", compose)
	}
	if !bytes.Contains(text, []byte(`"3306:3306"`)) {
		t.Errorf("%s does not publish port 3306", compose)
	}
}

// TestLowPrivQueryReachesOptimizerOnPublishedPort starts every compose path
// that boots the official MySQL image, connects to its published port as the
// non-admin account that file creates, and runs a statement the server plans
// with the optimizer. Each case fails while that server's version is affected.
func TestLowPrivQueryReachesOptimizerOnPublishedPort(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required to run the published MySQL server")
	}
	client, err := exec.LookPath("mysql")
	if err != nil {
		client, err = exec.LookPath("mariadb")
	}
	if err != nil {
		t.Fatal("a mysql protocol client is required")
	}

	root := repoRoot(t)
	devenv := filepath.Join(root, "devenv")
	script := filepath.Join(devenv, "create_docker_compose.sh")
	generated := []string{
		filepath.Join(devenv, "docker-compose.yaml"),
		filepath.Join(devenv, ".env"),
		filepath.Join(devenv, "conf.tmp"),
	}

	cases := []struct {
		name     string
		block    string
		compose  string
		dir      string
		service  string
		wantPort string
		extraEnv []string
	}{
		{name: "mysql block", block: "mysql", compose: filepath.Join(devenv, "docker-compose.yaml"), dir: devenv, service: "mysql", wantPort: "3306"},
		{name: "mysql_tests image", block: "mysql_tests", compose: filepath.Join(devenv, "docker-compose.yaml"), dir: devenv, service: "mysqltests", wantPort: "3306"},
		{name: "integration workflow override", block: "mysql_tests", compose: filepath.Join(devenv, "docker-compose.yaml"), dir: devenv, service: "mysqltests", wantPort: "3306", extraEnv: []string{"mysql_version=8.0.43"}},
		{name: "ha_test", compose: filepath.Join(root, "devenv/docker/ha_test/docker-compose.yaml"), dir: filepath.Join(root, "devenv/docker/ha_test"), service: "db", wantPort: "3306"},
		{name: "ha-test-unified-alerting", compose: filepath.Join(root, "devenv/docker/ha-test-unified-alerting/docker-compose.yaml"), dir: filepath.Join(root, "devenv/docker/ha-test-unified-alerting"), service: "db"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backups := backupGenerated(t, generated)
			t.Cleanup(func() {
				restoreGenerated(generated, backups)
			})
			if tc.block != "" {
				cmd := exec.Command(script, tc.block)
				cmd.Dir = devenv
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("create_docker_compose.sh %s: %v\n%s", tc.block, err, out)
				}
			}

			project := "cve-mysql-exposure"
			up := exec.Command("docker", "compose", "-p", project, "-f", tc.compose, "--project-directory", tc.dir, "up", "-d", "--build", tc.service)
			up.Env = append(os.Environ(), tc.extraEnv...)
			if out, err := up.CombinedOutput(); err != nil {
				t.Fatalf("compose up: %v\n%s", err, out)
			}
			t.Cleanup(func() {
				down := exec.Command("docker", "compose", "-p", project, "-f", tc.compose, "--project-directory", tc.dir, "down", "-v")
				down.Env = append(os.Environ(), tc.extraEnv...)
				_ = down.Run()
			})

			id := containerID(t, project, tc.service)
			user := containerEnv(t, id, "MYSQL_USER")
			password := containerEnv(t, id, "MYSQL_PASSWORD")
			database := containerEnv(t, id, "MYSQL_DATABASE")
			if user == "" || password == "" || database == "" {
				t.Fatal("mysql service did not receive database account settings")
			}
			port := publishedHostPort(t, id)
			if tc.wantPort != "" && port != tc.wantPort {
				t.Fatalf("host port for 3306 is %s, want %s", port, tc.wantPort)
			}

			cnf := filepath.Join(t.TempDir(), "client.cnf")
			contents := fmt.Sprintf("[client]\nuser=%s\npassword=%s\nhost=127.0.0.1\nport=%s\nprotocol=TCP\ndatabase=%s\n", user, password, port, database)
			if err := os.WriteFile(cnf, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := waitForMySQL(client, cnf, 120*time.Second); err != nil {
				t.Fatal(err)
			}

			versionRaw := query(t, client, cnf, "SELECT VERSION()")
			version, err := parseMySQLVersion(strings.TrimSpace(versionRaw))
			if err != nil {
				t.Fatal(err)
			}

			grants := query(t, client, cnf, "SHOW GRANTS")
			// USAGE ON *.* is the default empty global grant. Administrative
			// grants are global ALL, SUPER, or SYSTEM_USER; schema ALL is the
			// low-privileged account these files create.
			upper := strings.ToUpper(grants)
			for _, admin := range []string{"ALL PRIVILEGES ON *.*", "SUPER", "SYSTEM_USER"} {
				if strings.Contains(upper, admin) {
					t.Fatalf("account is not low-privileged:\n%s", grants)
				}
			}
			// The official image escapes underscores in the schema grant.
			normalized := strings.ReplaceAll(grants, `\`, "")
			if !strings.Contains(normalized, "ON `"+database+"`.*") && !strings.Contains(normalized, "ON "+database+".*") {
				t.Fatalf("account has no privilege on its schema:\n%s", grants)
			}

			// A primary-key lookup. Planning it goes through
			// Sql_cmd_dml::execute_inner, Query_expression::optimize, and JOIN::optimize.
			query(t, client, cnf, "DROP TABLE IF EXISTS optimizer_probe")
			query(t, client, cnf, "CREATE TABLE optimizer_probe (id INT NOT NULL PRIMARY KEY)")
			query(t, client, cnf, "INSERT INTO optimizer_probe (id) VALUES (1)")
			planRaw := query(t, client, cnf, "EXPLAIN FORMAT=JSON SELECT id FROM optimizer_probe WHERE id = 1")
			var plan struct {
				QueryBlock struct {
					Table struct {
						AccessType string `json:"access_type"`
					} `json:"table"`
				} `json:"query_block"`
			}
			if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
				t.Fatalf("explain plan is not JSON: %v\n%s", err, planRaw)
			}
			if plan.QueryBlock.Table.AccessType == "" {
				t.Fatalf("optimizer did not produce an access method:\n%s", planRaw)
			}
			if version.affected() {
				t.Fatalf("low-privileged account %q reached the optimizer on published port %s (access_type=%s) of MySQL %s, which is inside the affected range", user, port, plan.QueryBlock.Table.AccessType, version)
			}
		})
	}
}

func backupGenerated(t *testing.T, paths []string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err == nil {
			out[path] = body
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	return out
}

func restoreGenerated(paths []string, backups map[string][]byte) {
	for _, path := range paths {
		body, ok := backups[path]
		if !ok {
			_ = os.Remove(path)
			continue
		}
		_ = os.WriteFile(path, body, 0o644)
	}
}

func containerID(t *testing.T, project, service string) string {
	t.Helper()
	out, err := exec.Command("docker", "compose", "-p", project, "ps", "-q", service).Output()
	if err != nil {
		t.Fatalf("compose ps: %v", err)
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		t.Fatalf("service %s has no container", service)
	}
	return id
}

func containerEnv(t *testing.T, id, key string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{range .Config.Env}}{{printf \"%s\\n\" .}}{{end}}", id).Output()
	if err != nil {
		t.Fatalf("inspect env: %v", err)
	}
	prefix := key + "="
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

func publishedHostPort(t *testing.T, id string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{(index (index .NetworkSettings.Ports \"3306/tcp\") 0).HostPort}}", id).Output()
	if err != nil {
		t.Fatalf("inspect port: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func waitForMySQL(client, cnf string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last []byte
	for time.Now().Before(deadline) {
		cmd := exec.Command(client, "--defaults-extra-file="+cnf, "-N", "-e", "SELECT 1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		last = out
		time.Sleep(time.Second)
	}
	return fmt.Errorf("server did not accept a connection on the published port: %s", last)
}

func query(t *testing.T, client, cnf, statement string) string {
	t.Helper()
	cmd := exec.Command(client, "--defaults-extra-file="+cnf, "--batch", "--raw", "--skip-column-names", "-e", statement)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", statement, err, out)
	}
	return strings.TrimSpace(string(out))
}
