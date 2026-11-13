package mysqlpin

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Oracle's January 2026 Critical Patch Update lists MySQL Server 8.0.0-8.0.44,
// 8.4.0-8.4.7, and 9.0.0-9.5.0 as affected for the Optimizer defect tracked as
// CVE-2026-21968. These tests resolve the servers this repository actually
// starts and fail while any of them is still inside that range.

func TestDevenvMySQLBlockResolvesAffectedServer(t *testing.T) {
	root := repoRoot(t)
	generated := runCreateDockerCompose(t, root, "mysql")

	if !strings.Contains(generated.compose, "image: mysql:${mysql_version}") {
		t.Fatal("create_docker_compose.sh did not wire blocks/mysql image to mysql_version")
	}
	version := dotenv(generated.env, "mysql_version")
	if version == "" {
		t.Fatal("generated devenv env file has no mysql_version")
	}
	assertServerNotAffected(t, "devenv mysql block (create_docker_compose.sh mysql)", version)
	assertMySQLServerPublished(t, "devenv mysql block", generated.compose)
}

func TestDevenvMySQLTestsImageIsNotAffected(t *testing.T) {
	root := repoRoot(t)
	generated := runCreateDockerCompose(t, root, "mysql_tests")

	if !strings.Contains(generated.compose, "mysql_version=${mysql_version}") {
		t.Fatal("create_docker_compose.sh did not pass mysql_version into the mysql_tests build")
	}
	version := dotenv(generated.env, "mysql_version")
	assertServerNotAffected(t, "devenv mysql_tests block (create_docker_compose.sh mysql_tests)", version)

	dockerfile := read(t, filepath.Join(root, "devenv/docker/blocks/mysql_tests/Dockerfile"))
	arg := firstMatch(t, dockerfile, regexp.MustCompile(`ARG mysql_version=(\d+\.\d+\.\d+)`))
	assertServerNotAffected(t, "devenv/docker/blocks/mysql_tests/Dockerfile ARG default", arg)
	if !strings.Contains(dockerfile, "FROM mysql:${mysql_version}") {
		t.Fatal("mysql_tests Dockerfile does not start the server from the mysql_version build arg")
	}
	assertMySQLServerPublished(t, "devenv mysql_tests block", generated.compose)
}

func TestWorkflowAndComposePinsAreNotAffected(t *testing.T) {
	root := repoRoot(t)
	versionPattern := regexp.MustCompile(`(?:mysql_version=|image:\s*mysql:|FROM mysql:)(\d+\.\d+\.\d+)`)
	var found int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !pinFile(path) {
			return nil
		}
		body := read(t, path)
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			t.Fatal(relErr)
		}
		for _, match := range versionPattern.FindAllStringSubmatchIndex(body, -1) {
			found++
			version := body[match[2]:match[3]]
			assertServerNotAffected(t, rel, version)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("found no MySQL server version pins to check")
	}
}

func TestMakeExportsWorkflowMySQLVersion(t *testing.T) {
	// GNU make exports a command-line variable into the recipe environment.
	// `make devenv sources=mysql_tests mysql_version=<pin>` therefore overrides
	// the block .env when Compose loads the project (OS environment wins).
	root := repoRoot(t)
	workflow := read(t, filepath.Join(root, ".github/workflows/pr-test-integration.yml"))
	pins := regexp.MustCompile(`mysql_version=(\d+\.\d+\.\d+)`).FindAllStringSubmatch(workflow, -1)
	if len(pins) == 0 {
		t.Fatal("workflow does not pass mysql_version to make devenv")
	}
	for _, pin := range pins {
		cmd := exec.Command("make", "-f", "-", "show", "mysql_version="+pin[1])
		cmd.Stdin = strings.NewReader("show:\n\t@printf '%s' \"$$mysql_version\"\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make did not export mysql_version: %v\n%s", err, out)
		}
		if string(out) != pin[1] {
			t.Fatalf("make recipe saw %q, workflow requested %s", out, pin[1])
		}
		assertServerNotAffected(t, "workflow make mysql_version override", pin[1])
	}
}

func TestFixedVersionsAreOutsideTheAffectedRange(t *testing.T) {
	for _, version := range []string{"8.0.45", "8.4.8", "9.5.1", "9.7.4"} {
		if affected, err := mysqlServerAffected(version); err != nil || affected {
			t.Errorf("%s should be outside the affected ranges (affected=%v err=%v)", version, affected, err)
		}
	}
	for _, version := range []string{"8.0.0", "8.0.32", "8.0.43", "8.0.44", "8.4.0", "8.4.7", "9.0.0", "9.5.0"} {
		if affected, err := mysqlServerAffected(version); err != nil || !affected {
			t.Errorf("%s should be inside the affected ranges (affected=%v err=%v)", version, affected, err)
		}
	}
}

type generatedCompose struct {
	compose string
	env     string
}

func runCreateDockerCompose(t *testing.T, root, block string) generatedCompose {
	t.Helper()
	devenv := filepath.Join(root, "devenv")
	composePath := filepath.Join(devenv, "docker-compose.yaml")
	envPath := filepath.Join(devenv, ".env")
	configPath := filepath.Join(devenv, "conf.tmp")
	restore := preserve(t, composePath, envPath, configPath)
	t.Cleanup(restore)

	cmd := exec.Command("./create_docker_compose.sh", block)
	cmd.Dir = devenv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("create_docker_compose.sh %s: %v\n%s", block, err, out)
	}
	return generatedCompose{compose: read(t, composePath), env: read(t, envPath)}
}

func preserve(t *testing.T, paths ...string) func() {
	t.Helper()
	type saved struct {
		path    string
		content []byte
		present bool
	}
	var previous []saved
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		previous = append(previous, saved{path: path, content: content, present: err == nil})
	}
	return func() {
		for _, item := range previous {
			if !item.present {
				_ = os.Remove(item.path)
				continue
			}
			if err := os.WriteFile(item.path, item.content, 0o644); err != nil {
				t.Errorf("restore %s: %v", item.path, err)
			}
		}
	}
}

func assertServerNotAffected(t *testing.T, source, version string) {
	t.Helper()
	affected, err := mysqlServerAffected(version)
	if err != nil {
		t.Errorf("%s: %v", source, err)
		return
	}
	if affected {
		t.Errorf("%s pins MySQL Server %s, which is inside the affected ranges 8.0.0-8.0.44, 8.4.0-8.4.7, 9.0.0-9.5.0", source, version)
	}
}

func assertMySQLServerPublished(t *testing.T, source, compose string) {
	t.Helper()
	if !regexp.MustCompile(`(?m)(?:-\s+mysqld\s*$|"mysqld"|\[mysqld(?:[,\]]|$))`).MatchString(compose) {
		t.Errorf("%s does not start mysqld", source)
	}
	if !publishesAllInterfaces(compose, "3306") {
		t.Errorf("%s does not publish container port 3306 on all host interfaces", source)
	}
	user := envKey(compose, "MYSQL_USER")
	database := envKey(compose, "MYSQL_DATABASE")
	if user == "" || user == "root" || database == "" {
		t.Errorf("%s does not configure a non-root MYSQL_USER with a MYSQL_DATABASE", source)
	}
}

func publishesAllInterfaces(compose, containerPort string) bool {
	for _, line := range strings.Split(compose, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		line = strings.Trim(line, `"'`)
		if line == "" || strings.Contains(line, " ") {
			continue
		}
		parts := strings.Split(line, ":")
		switch len(parts) {
		case 1:
			if parts[0] == containerPort {
				return true
			}
		case 2:
			if parts[1] == containerPort && !strings.Contains(parts[0], ".") {
				return true
			}
		}
	}
	return false
}

func envKey(compose, key string) string {
	pattern := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(key) + `:\s*(\S+)\s*$`)
	match := pattern.FindStringSubmatch(compose)
	if match == nil {
		return ""
	}
	return strings.Trim(match[1], `"'`)
}

func pinFile(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml", "Dockerfile", ".env":
		return true
	}
	return strings.HasSuffix(path, ".yml") && strings.Contains(path, string(filepath.Separator)+".github"+string(filepath.Separator)+"workflows"+string(filepath.Separator))
}

func mysqlServerAffected(raw string) (bool, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false, strconv.ErrSyntax
	}
	nums := make([]int, 3)
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return false, err
		}
		nums[i] = n
	}
	major, minor, patch := nums[0], nums[1], nums[2]
	switch {
	case major == 8 && minor == 0 && patch >= 0 && patch <= 44:
		return true, nil
	case major == 8 && minor == 4 && patch >= 0 && patch <= 7:
		return true, nil
	case major == 9 && (minor < 5 || (minor == 5 && patch == 0)) && minor >= 0:
		return true, nil
	default:
		return false, nil
	}
}

func dotenv(content, key string) string {
	prefix := key + "="
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.Trim(strings.TrimPrefix(line, prefix), `"'`)
		}
	}
	return ""
}

func firstMatch(t *testing.T, content string, pattern *regexp.Regexp) string {
	t.Helper()
	match := pattern.FindStringSubmatch(content)
	if match == nil {
		t.Fatalf("pattern %s not found", pattern)
	}
	return match[1]
}

func read(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "devenv", "create_docker_compose.sh")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root")
		}
		dir = parent
	}
}
