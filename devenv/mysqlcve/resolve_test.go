package mysqlcve

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Oracle's April 2026 CPU lists these MySQL Server releases as affected by the
// optimizer availability bug (hang or repeatable crash for a low-privileged
// network client): 8.0.0-8.0.45, 8.4.0-8.4.8, and 9.0.0-9.6.0.
var optimizerDOSRanges = [][2]version{
	{version{8, 0, 0}, version{8, 0, 45}},
	{version{8, 4, 0}, version{8, 4, 8}},
	{version{9, 0, 0}, version{9, 6, 0}},
}

type version struct {
	major, minor, patch int
}

func (v version) String() string {
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}

func (v version) cmp(o version) int {
	if v.major != o.major {
		return v.major - o.major
	}
	if v.minor != o.minor {
		return v.minor - o.minor
	}
	return v.patch - o.patch
}

func affectedOptimizerDOS(v version) bool {
	for _, r := range optimizerDOSRanges {
		if v.cmp(r[0]) >= 0 && v.cmp(r[1]) <= 0 {
			return true
		}
	}
	return false
}

var versionPrefix = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

func parseVersion(tag string) (version, bool) {
	m := versionPrefix.FindStringSubmatch(tag)
	if m == nil {
		return version{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return version{major, minor, patch}, true
}

func TestOptimizerDOSRangeBoundaries(t *testing.T) {
	affected := []string{"8.0.0", "8.0.32", "8.0.43", "8.0.45", "8.4.0", "8.4.8", "9.0.0", "9.6.0"}
	safe := []string{"8.0.46", "8.4.9", "9.6.1", "9.7.4", "5.7.41"}
	for _, tag := range affected {
		v, ok := parseVersion(tag)
		if !ok || !affectedOptimizerDOS(v) {
			t.Errorf("%s should be inside the optimizer DOS ranges", tag)
		}
	}
	for _, tag := range safe {
		v, ok := parseVersion(tag)
		if !ok || affectedOptimizerDOS(v) {
			t.Errorf("%s should be outside the optimizer DOS ranges", tag)
		}
	}
}

func TestMySQLServerPinsAreOutsideOptimizerDOSRanges(t *testing.T) {
	root := repoRoot(t)

	t.Run("devenv mysql block", func(t *testing.T) {
		compose, envFile := generateBlock(t, root, "mysql")
		resolved := substitute(compose, nil, parseDotEnv(envFile))
		for _, image := range imageRefs(resolved) {
			requireSafeMySQL(t, "devenv/docker/blocks/mysql", image)
		}
	})

	t.Run("mysql_tests Dockerfile default", func(t *testing.T) {
		text := readFile(t, filepath.Join(root, "devenv/docker/blocks/mysql_tests/Dockerfile"))
		for _, image := range dockerfileImages(text) {
			requireSafeMySQL(t, "devenv/docker/blocks/mysql_tests/Dockerfile", image)
		}
	})

	t.Run("mysql_tests compose default", func(t *testing.T) {
		compose, envFile := generateBlock(t, root, "mysql_tests")
		resolved := substitute(compose, nil, parseDotEnv(envFile))
		for _, tag := range buildArgValues(resolved, "mysql_version") {
			requireSafeMySQL(t, "devenv mysql_tests build", "mysql:"+tag)
		}
	})

	t.Run("ci workflow make overrides", func(t *testing.T) {
		workflow := readFile(t, filepath.Join(root, ".github/workflows/pr-test-integration.yml"))
		versions := workflowMySQLVersions(workflow)
		if len(versions) == 0 {
			t.Fatal("pr-test-integration.yml no longer passes mysql_version to make devenv")
		}
		for _, pinned := range versions {
			pinned := pinned
			t.Run(pinned, func(t *testing.T) {
				exported := makeExportedMySQLVersion(t, root, pinned)
				compose, envFile := generateBlock(t, root, "mysql_tests")
				resolved := substitute(compose, map[string]string{"mysql_version": exported}, parseDotEnv(envFile))
				values := buildArgValues(resolved, "mysql_version")
				if len(values) == 0 {
					t.Fatal("mysql_tests compose does not pass a mysql_version build arg")
				}
				for _, tag := range values {
					requireSafeMySQL(t, "make devenv sources=mysql_tests mysql_version="+pinned, "mysql:"+tag)
				}
			})
		}
	})

	t.Run("ha_test compose", func(t *testing.T) {
		text := readFile(t, filepath.Join(root, "devenv/docker/ha_test/docker-compose.yaml"))
		for _, image := range imageRefs(text) {
			requireSafeMySQL(t, "devenv/docker/ha_test/docker-compose.yaml", image)
		}
	})

	t.Run("ha-test-unified-alerting compose", func(t *testing.T) {
		text := readFile(t, filepath.Join(root, "devenv/docker/ha-test-unified-alerting/docker-compose.yaml"))
		for _, image := range imageRefs(text) {
			requireSafeMySQL(t, "devenv/docker/ha-test-unified-alerting/docker-compose.yaml", image)
		}
	})
}

func requireSafeMySQL(t *testing.T, where, image string) {
	t.Helper()
	name, tag := splitImage(image)
	if !isMySQLServerImage(name) {
		return
	}
	v, ok := parseVersion(tag)
	if !ok {
		t.Fatalf("%s image %s is not pinned to a major.minor.patch release outside the optimizer DOS ranges", where, image)
	}
	if affectedOptimizerDOS(v) {
		t.Fatalf("%s resolves to MySQL Server %s, inside the optimizer DOS ranges 8.0.0-8.0.45, 8.4.0-8.4.8, and 9.0.0-9.6.0", where, v)
	}
}

func isMySQLServerImage(name string) bool {
	name = strings.TrimPrefix(name, "docker.io/")
	name = strings.TrimPrefix(name, "index.docker.io/")
	switch name {
	case "mysql", "library/mysql", "mysql/mysql-server":
		return true
	default:
		return false
	}
}

func splitImage(ref string) (name, tag string) {
	ref = strings.Trim(strings.TrimSpace(ref), `"'`)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, "latest"
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func generateBlock(t *testing.T, root, block string) (compose, envFile string) {
	t.Helper()
	devenv := filepath.Join(root, "devenv")
	cmd := exec.Command("bash", filepath.Join(devenv, "create_docker_compose.sh"), block)
	cmd.Dir = devenv
	out, err := cmd.CombinedOutput()
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(devenv, "docker-compose.yaml"))
		_ = os.Remove(filepath.Join(devenv, ".env"))
		_ = os.Remove(filepath.Join(devenv, "conf.tmp"))
	})
	if err != nil {
		t.Fatalf("create_docker_compose.sh %s: %v\n%s", block, err, out)
	}
	return readFile(t, filepath.Join(devenv, "docker-compose.yaml")), readFile(t, filepath.Join(devenv, ".env"))
}

// makeExportedMySQLVersion runs the repository Makefile the way CI does
// (`make ... mysql_version=<value>`) and returns the value exported into the
// recipe environment. Compose gives that shell value precedence over devenv/.env.
func makeExportedMySQLVersion(t *testing.T, root, value string) string {
	t.Helper()
	cmd := exec.Command("make", "-f", "Makefile", "mysql_version="+value, "--eval",
		`show_mysql_version: ; @printf '%s' "$$mysql_version"`, "show_mysql_version")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("make mysql_version=%s: %v", value, err)
	}
	got := string(out)
	if got == "" {
		t.Fatalf("make mysql_version=%s exported an empty value", value)
	}
	return got
}

func parseDotEnv(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		sep := strings.IndexAny(line, "=:")
		if sep <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:sep])
		val := strings.TrimSpace(line[sep+1:])
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		} else if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		out[key] = val
	}
	return out
}

var bracedVar = regexp.MustCompile(`\$\{([_A-Za-z][_A-Za-z0-9]*)}`)

// substitute applies Compose's direct ${VAR} substitution. A variable set in
// the shell wins over the project .env file. An unset variable becomes empty.
func substitute(text string, shell, dotenv map[string]string) string {
	return bracedVar.ReplaceAllStringFunc(text, func(match string) string {
		name := bracedVar.FindStringSubmatch(match)[1]
		if v, ok := shell[name]; ok {
			return v
		}
		if v, ok := dotenv[name]; ok {
			return v
		}
		return ""
	})
}

func imageRefs(compose string) []string {
	var refs []string
	for _, line := range strings.Split(compose, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, "image:") {
			continue
		}
		ref := strings.TrimSpace(strings.TrimPrefix(trim, "image:"))
		ref = strings.Trim(ref, `"'`)
		if ref != "" {
			refs = append(refs, ref)
		}
	}
	return refs
}

func buildArgValues(compose, name string) []string {
	var values []string
	listItem := regexp.MustCompile(`^-\s*` + regexp.QuoteMeta(name) + `=(.*)$`)
	mapping := regexp.MustCompile(`^` + regexp.QuoteMeta(name) + `\s*:\s*(.*)$`)
	for _, line := range strings.Split(compose, "\n") {
		trim := strings.TrimSpace(line)
		if m := listItem.FindStringSubmatch(trim); m != nil {
			values = append(values, strings.Trim(m[1], `"'`))
			continue
		}
		if m := mapping.FindStringSubmatch(trim); m != nil {
			values = append(values, strings.Trim(m[1], `"'`))
		}
	}
	return values
}

func dockerfileImages(text string) []string {
	defaults := map[string]string{}
	var images []string
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "ARG ") {
			body := strings.TrimSpace(strings.TrimPrefix(trim, "ARG "))
			key, val, ok := strings.Cut(body, "=")
			if ok {
				defaults[strings.TrimSpace(key)] = strings.TrimSpace(val)
			}
			continue
		}
		if strings.HasPrefix(trim, "FROM ") {
			fields := strings.Fields(strings.TrimPrefix(trim, "FROM "))
			if len(fields) == 0 {
				continue
			}
			ref := substitute(fields[0], nil, defaults)
			images = append(images, ref)
		}
	}
	return images
}

var workflowVersion = regexp.MustCompile(`mysql_version=([0-9]+\.[0-9]+\.[0-9]+)`)

func workflowMySQLVersions(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range workflowVersion.FindAllStringSubmatch(text, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}
