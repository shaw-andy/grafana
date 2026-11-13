package mysqlimage

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Oracle's July 2025 CPU describes the InnoDB issue as affecting MySQL Server
// 8.0.0-8.0.42, 8.4.0-8.4.5, and 9.0.0-9.3.0. These tests resolve the MySQL
// images the dev and HA environments actually start and fail while a resolved
// server version is inside that range.
//
// The documented bitnami/mysql image in pkg/storage/unified/README.md is not
// covered here.

func TestAdvisoryBounds(t *testing.T) {
	t.Parallel()
	inside := []string{"8.0.0", "8.0.32", "8.0.42", "8.4.0", "8.4.5", "9.0.0", "9.2.3", "9.3.0"}
	outside := []string{"8.0.43", "8.4.6", "9.3.1", "5.7.44", "8.1.0"}
	for _, v := range inside {
		if !versionInAdvisory(t, v) {
			t.Fatalf("version %s should be inside the advisory range", v)
		}
	}
	for _, v := range outside {
		if versionInAdvisory(t, v) {
			t.Fatalf("version %s should be outside the advisory range", v)
		}
	}
}

func TestHATestComposeMySQLOutsideAdvisory(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	cfg := composeConfig(t, filepath.Join(root, "devenv", "docker", "ha_test"), nil)
	assertGrafanaUsesMySQLService(t, cfg, "devenv/docker/ha_test")
	version := serviceMySQLVersion(t, cfg, "db")
	requireOutsideAdvisory(t, "devenv/docker/ha_test db", version)
}

func TestUnifiedAlertingHAComposeMySQLOutsideAdvisory(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	cfg := composeConfig(t, filepath.Join(root, "devenv", "docker", "ha-test-unified-alerting"), nil)
	assertGrafanaUsesMySQLService(t, cfg, "devenv/docker/ha-test-unified-alerting")
	version := serviceMySQLVersion(t, cfg, "db")
	requireOutsideAdvisory(t, "devenv/docker/ha-test-unified-alerting db", version)
}

func TestDevenvMySQLBlockOutsideAdvisory(t *testing.T) {
	t.Parallel()
	dir := renderDevenv(t, "mysql")
	cfg := composeConfig(t, dir, nil)
	version := serviceMySQLVersion(t, cfg, "mysql")
	requireOutsideAdvisory(t, "make devenv sources=mysql", version)
}

func TestDevenvMySQLTestsDefaultOutsideAdvisory(t *testing.T) {
	t.Parallel()
	dir := renderDevenv(t, "mysql_tests")
	cfg := composeConfig(t, dir, nil)
	version := serviceMySQLVersion(t, cfg, "mysqltests")
	requireOutsideAdvisory(t, "make devenv sources=mysql_tests (default mysql_version)", version)

	dockerfile := filepath.Join(dir, "docker", "blocks", "mysql_tests", "Dockerfile")
	fallback := dockerfileDefaultMySQL(t, dockerfile)
	requireOutsideAdvisory(t, "devenv/docker/blocks/mysql_tests/Dockerfile ARG mysql_version", fallback)
}

func TestForkPRMySQLOverrideOutsideAdvisory(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	workflow := filepath.Join(root, ".github", "workflows", "pr-test-integration.yml")
	body, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatal(err)
	}
	pins := regexp.MustCompile(`mysql_version=(\d+\.\d+\.\d+)`).FindAllStringSubmatch(string(body), -1)
	if len(pins) == 0 {
		t.Fatal(".github/workflows/pr-test-integration.yml does not pin mysql_version")
	}
	dir := renderDevenv(t, "mysql_tests")
	seen := map[string]bool{}
	for _, pin := range pins {
		version := pin[1]
		if seen[version] {
			continue
		}
		seen[version] = true
		cfg := composeConfig(t, dir, []string{"mysql_version=" + version})
		resolved := serviceMySQLVersion(t, cfg, "mysqltests")
		if resolved != version {
			t.Fatalf("mysql_version=%s did not override the rendered mysql_tests image (resolved %s)", version, resolved)
		}
		requireOutsideAdvisory(t, "pr-test-integration.yml mysql_version", resolved)
	}
}

func assertGrafanaUsesMySQLService(t *testing.T, cfg map[string]any, what string) {
	t.Helper()
	services := servicesOf(t, cfg)
	var checked int
	for name, raw := range services {
		svc, _ := raw.(map[string]any)
		env := envOf(svc)
		dbType, ok := env["GF_DATABASE_TYPE"]
		if !ok {
			continue
		}
		checked++
		if dbType != "mysql" {
			t.Fatalf("%s service %s sets GF_DATABASE_TYPE=%s", what, name, dbType)
		}
		host := env["GF_DATABASE_HOST"]
		if !strings.HasPrefix(host, "db:") {
			t.Fatalf("%s service %s GF_DATABASE_HOST %q does not use the db service", what, name, host)
		}
		if _, ok := services["db"]; !ok {
			t.Fatalf("%s has no db service for %s to use", what, name)
		}
	}
	if checked == 0 {
		t.Fatalf("%s resolved no service with GF_DATABASE_TYPE", what)
	}
}

func serviceMySQLVersion(t *testing.T, cfg map[string]any, service string) string {
	t.Helper()
	services := servicesOf(t, cfg)
	raw, ok := services[service]
	if !ok {
		t.Fatalf("compose config has no %s service", service)
	}
	svc, _ := raw.(map[string]any)
	if img, _ := svc["image"].(string); img != "" {
		version, ok := versionFromImage(img)
		if !ok {
			t.Fatalf("service %s image %q is not a pinned mysql version", service, img)
		}
		return version
	}
	build, _ := svc["build"].(map[string]any)
	args, _ := build["args"].(map[string]any)
	arg, _ := args["mysql_version"].(string)
	if arg == "" {
		t.Fatalf("service %s has no mysql image and no mysql_version build arg", service)
	}
	context, _ := build["context"].(string)
	dockerfile := filepath.Join(context, "Dockerfile")
	from := dockerfileFrom(t, dockerfile)
	if from != "mysql:${mysql_version}" {
		t.Fatalf("service %s Dockerfile FROM %q does not use the mysql_version build arg", service, from)
	}
	if _, ok := versionFromImage("mysql:" + arg); !ok {
		t.Fatalf("service %s mysql_version %q is not a pinned mysql version", service, arg)
	}
	return arg
}

func dockerfileDefaultMySQL(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ARG mysql_version=(\d+\.\d+\.\d+)\s*$`).FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("%s has no ARG mysql_version default", path)
	}
	if dockerfileFrom(t, path) != "mysql:${mysql_version}" {
		t.Fatalf("%s FROM does not use ${mysql_version}", path)
	}
	return m[1]
}

func dockerfileFrom(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FROM ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "FROM "))
		}
	}
	t.Fatalf("%s has no FROM", path)
	return ""
}

func renderDevenv(t *testing.T, source string) string {
	t.Helper()
	root := repoRoot(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "create_docker_compose.sh"), mustRead(t, filepath.Join(root, "devenv", "create_docker_compose.sh")), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(root, "devenv", "docker", "compose_header.yml"), filepath.Join(dir, "docker", "compose_header.yml"))
	copyDir(t, filepath.Join(root, "devenv", "docker", "blocks", source), filepath.Join(dir, "docker", "blocks", source))

	cmd := exec.Command("./create_docker_compose.sh", source)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("create_docker_compose.sh %s: %v\n%s", source, err, redact(string(out)))
	}
	return dir
}

func composeConfig(t *testing.T, dir string, env []string) map[string]any {
	t.Helper()
	bin, baseArgs := composeCommand(t)
	args := append(append([]string{}, baseArgs...), "config", "--format", "json")
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("compose config in %s: %v\n%s", dir, err, redact(stderr))
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("decode compose config: %v", err)
	}
	return cfg
}

func composeCommand(t *testing.T) (string, []string) {
	t.Helper()
	if docker, err := exec.LookPath("docker"); err == nil {
		probe := exec.Command(docker, "compose", "version")
		if err := probe.Run(); err == nil {
			return docker, []string{"compose"}
		}
	}
	if path, err := exec.LookPath("docker-compose"); err == nil {
		return path, nil
	}
	t.Fatal("docker compose or docker-compose is required to resolve the image the environment starts")
	return "", nil
}

func servicesOf(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	services, _ := cfg["services"].(map[string]any)
	if services == nil {
		t.Fatal("compose config has no services")
	}
	return services
}

func envOf(svc map[string]any) map[string]string {
	out := map[string]string{}
	switch env := svc["environment"].(type) {
	case map[string]any:
		for k, v := range env {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	case []any:
		for _, item := range env {
			s, _ := item.(string)
			key, val, ok := strings.Cut(s, "=")
			if ok {
				out[key] = val
			}
		}
	}
	return out
}

func requireOutsideAdvisory(t *testing.T, what, version string) {
	t.Helper()
	if versionInAdvisory(t, version) {
		t.Fatalf("%s resolves to MySQL %s, inside the InnoDB advisory ranges 8.0.0-8.0.42, 8.4.0-8.4.5, and 9.0.0-9.3.0", what, version)
	}
}

func versionInAdvisory(t *testing.T, version string) bool {
	t.Helper()
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		t.Fatalf("version %q is not major.minor.patch", version)
	}
	nums := [3]int{}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			t.Fatalf("version %q: %v", version, err)
		}
		nums[i] = n
	}
	return inRange(nums, [3]int{8, 0, 0}, [3]int{8, 0, 42}) ||
		inRange(nums, [3]int{8, 4, 0}, [3]int{8, 4, 5}) ||
		inRange(nums, [3]int{9, 0, 0}, [3]int{9, 3, 0})
}

func inRange(v, lo, hi [3]int) bool {
	return cmpVer(v, lo) >= 0 && cmpVer(v, hi) <= 0
}

func cmpVer(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return 0
}

var mysqlTag = regexp.MustCompile(`^(\d+\.\d+\.\d+)`)

func versionFromImage(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon < 0 || colon < slash {
		return "", false
	}
	name := ref[:colon]
	if slash >= 0 {
		name = name[slash+1:]
	}
	if name != "mysql" {
		return "", false
	}
	m := mysqlTag.FindStringSubmatch(ref[colon+1:])
	if m == nil {
		return "", false
	}
	return m[1], true
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found from the test working directory")
		}
		dir = parent
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, mustRead(t, src), info.Mode()); err != nil {
		t.Fatal(err)
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		copyFile(t, path, target)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func redact(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "DATA_SOURCE") {
			b.WriteString("[redacted]\n")
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
