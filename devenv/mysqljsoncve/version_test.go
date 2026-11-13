package mysqljsoncve

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// affectedRanges are the MySQL Server versions the April 2026 Oracle CPU lists
// for the Server: JSON availability issue. Each pair is inclusive.
var affectedRanges = [][2]version{
	{{8, 0, 0}, {8, 0, 45}},
	{{8, 4, 0}, {8, 4, 8}},
	{{9, 0, 0}, {9, 6, 0}},
}

type version struct {
	major, minor, patch int
}

func (v version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
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

func affected(v version) bool {
	for _, r := range affectedRanges {
		if v.cmp(r[0]) >= 0 && v.cmp(r[1]) <= 0 {
			return true
		}
	}
	return false
}

func parseVersion(s string) (version, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	nums := [3]int{}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return version{}, false
		}
		nums[i] = n
	}
	return version{nums[0], nums[1], nums[2]}, true
}

func TestAffectedRangeBoundaries(t *testing.T) {
	inside := []string{"8.0.0", "8.0.32", "8.0.43", "8.0.45", "8.4.0", "8.4.8", "9.0.0", "9.3.0", "9.6.0"}
	outside := []string{"7.5.41", "8.0.46", "8.4.9", "8.4.13", "9.6.1", "9.7.4", "26.10.0"}
	for _, raw := range inside {
		v, ok := parseVersion(raw)
		if !ok || !affected(v) {
			t.Fatalf("%s must be inside the affected ranges", raw)
		}
	}
	for _, raw := range outside {
		v, ok := parseVersion(raw)
		if !ok || affected(v) {
			t.Fatalf("%s must be outside the affected ranges", raw)
		}
	}
}

type pin struct {
	source  string
	version version
	detail  string
}

func TestMySQLServerPinsAreOutsideJSONAvailabilityRanges(t *testing.T) {
	root := repoRoot(t)
	var pins []pin

	pins = append(pins, literalPins(t, root)...)
	pins = append(pins, assembledBlockPins(t, root)...)

	if len(pins) == 0 {
		t.Fatal("found no MySQL server version pins to check")
	}

	var bad []string
	for _, p := range pins {
		if affected(p.version) {
			bad = append(bad, fmt.Sprintf("%s -> %s (%s)", p.source, p.version, p.detail))
		}
	}
	if len(bad) > 0 {
		t.Fatalf("MySQL Server is pinned inside the affected ranges (8.0.0-8.0.45, 8.4.0-8.4.8, 9.0.0-9.6.0):\n%s", strings.Join(bad, "\n"))
	}
}

func literalPins(t *testing.T, root string) []pin {
	t.Helper()
	imageRef := regexp.MustCompile(`(?i)(?:^|[\s"'=])(?:[\w./-]+/)?mysql:(\d+\.\d+\.\d+)\b`)
	versionAssign := regexp.MustCompile(`(?m)^(?:ARG\s+)?mysql_version=(\d+\.\d+\.\d+)\s*$`)
	var pins []pin
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "mysqljsoncve" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == filepath.Join("devenv", ".env") || rel == filepath.Join("devenv", "docker-compose.yaml") || rel == filepath.Join("devenv", "conf.tmp") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		name := strings.ToLower(d.Name())
		if ext != ".yml" && ext != ".yaml" && ext != ".env" && ext != ".md" && name != "dockerfile" && !strings.HasPrefix(name, "dockerfile") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		for _, match := range imageRef.FindAllStringSubmatch(text, -1) {
			v, ok := parseVersion(match[1])
			if !ok {
				continue
			}
			pins = append(pins, pin{source: rel, version: v, detail: "image tag mysql:" + match[1]})
		}
		for _, match := range versionAssign.FindAllStringSubmatch(text, -1) {
			v, ok := parseVersion(match[1])
			if !ok {
				continue
			}
			pins = append(pins, pin{source: rel, version: v, detail: "mysql_version assignment"})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func assembledBlockPins(t *testing.T, root string) []pin {
	t.Helper()
	var pins []pin
	for _, block := range []string{"mysql", "mysql_tests"} {
		env, compose := assembleBlock(t, root, block)
		version, ok := env["mysql_version"]
		if !ok {
			t.Fatalf("assembled %s block did not publish mysql_version", block)
		}
		resolved, ok := parseVersion(version)
		if !ok {
			t.Fatalf("assembled %s mysql_version %q is not a numeric server version", block, version)
		}
		detail := exposureDetail(compose, version)
		pins = append(pins, pin{
			source:  "devenv create_docker_compose.sh " + block,
			version: resolved,
			detail:  "default env resolution; " + detail,
		})
		// CI only starts mysql_tests with an explicit make variable. make exports
		// that variable into the recipe, and Compose keeps it ahead of .env.
		if block != "mysql_tests" {
			continue
		}
		for _, override := range workflowOverrides(t, root) {
			over, ok := parseVersion(override.version)
			if !ok {
				t.Fatalf("workflow override %q is not a numeric server version", override.version)
			}
			pins = append(pins, pin{
				source:  override.source,
				version: over,
				detail:  "shell mysql_version overrides assembled .env (" + version + "); " + exposureDetail(compose, override.version),
			})
		}
	}
	return pins
}

type override struct {
	source, version string
}

func workflowOverrides(t *testing.T, root string) []override {
	t.Helper()
	pattern := regexp.MustCompile(`mysql_version=(\d+\.\d+\.\d+)`)
	var found []override
	err := filepath.WalkDir(filepath.Join(root, ".github", "workflows"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, line := range bytes.Split(body, []byte{'\n'}) {
			if !bytes.Contains(line, []byte("devenv")) || !bytes.Contains(line, []byte("mysql_version=")) {
				continue
			}
			match := pattern.FindSubmatch(line)
			if match == nil {
				continue
			}
			found = append(found, override{source: rel, version: string(match[1])})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("expected CI workflow overrides for the mysql_tests block")
	}
	return found
}

func assembleBlock(t *testing.T, root, block string) (map[string]string, string) {
	t.Helper()
	devenv := filepath.Join(root, "devenv")
	composePath := filepath.Join(devenv, "docker-compose.yaml")
	envPath := filepath.Join(devenv, ".env")
	confPath := filepath.Join(devenv, "conf.tmp")
	t.Cleanup(func() {
		_ = os.Remove(composePath)
		_ = os.Remove(envPath)
		_ = os.Remove(confPath)
	})
	cmd := exec.Command("./create_docker_compose.sh", block)
	cmd.Dir = devenv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("create_docker_compose.sh %s: %v\n%s", block, err, out)
	}
	envBody, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	return parseEnv(envBody), string(compose)
}

func parseEnv(body []byte) map[string]string {
	env := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[key] = value
	}
	return env
}

func exposureDetail(compose, version string) string {
	resolved := strings.ReplaceAll(compose, "${mysql_version}", version)
	published := strings.Contains(resolved, "3306:3306") || strings.Contains(resolved, "\"3306:3306\"") || regexp.MustCompile(`(?m)^\s+-\s+3306\s*$`).MatchString(resolved)
	userSet := false
	for _, line := range strings.Split(resolved, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "MYSQL_USER:") {
			name := strings.TrimSpace(strings.TrimPrefix(trimmed, "MYSQL_USER:"))
			if name != "" && name != "root" {
				userSet = true
			}
		}
	}
	port := "container port 3306 is not published"
	if published {
		port = "port 3306 is published"
	}
	account := "no non-root MYSQL_USER"
	if userSet {
		account = "MYSQL_USER is a non-root account"
	}
	image := "unresolved image"
	if strings.Contains(resolved, "mysql:"+version) || strings.Contains(resolved, "mysql_version="+version) {
		image = "server image mysql:" + version
	}
	return image + "; " + port + "; " + account
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
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
