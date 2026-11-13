package docker_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// CVE-2026-22017 affects MySQL Server 8.0.0–8.0.45, 8.4.0–8.4.8, and 9.0.0–9.6.0.
// These tests resolve every image the repository actually starts and fail while
// that image is still inside one of those ranges.
func TestMySQLServerImageOutsideCVE202622017(t *testing.T) {
	repo := repoRoot(t)
	devenv := copyDevenv(t, repo)

	t.Run("devenv mysql block", func(t *testing.T) {
		runCreateCompose(t, devenv, "mysql")
		cfg := composeConfig(t, devenv, nil)
		requireSafeMySQL(t, "devenv mysql block", cfg.Services["mysql"].Image)
	})

	t.Run("devenv mysql_tests build", func(t *testing.T) {
		runCreateCompose(t, devenv, "mysql_tests")
		cfg := composeConfig(t, devenv, nil)
		image := mysqlTestsImage(t, repo, cfg.Services["mysqltests"].Build)
		requireSafeMySQL(t, "devenv mysql_tests build", image)
	})

	t.Run("mysql_tests Dockerfile default", func(t *testing.T) {
		image := mysqlTestsImage(t, repo, nil)
		requireSafeMySQL(t, "mysql_tests Dockerfile default", image)
	})

	t.Run("integration workflow overrides", func(t *testing.T) {
		versions := workflowMySQLVersions(t, filepath.Join(repo, ".github/workflows/pr-test-integration.yml"))
		for _, version := range versions {
			runCreateCompose(t, devenv, "mysql_tests")
			cfg := composeConfig(t, devenv, []string{"mysql_version=" + version})
			image := mysqlTestsImage(t, repo, cfg.Services["mysqltests"].Build)
			requireSafeMySQL(t, "workflow mysql_version="+version, image)
		}
	})

	t.Run("ha_test", func(t *testing.T) {
		cfg := composeFileConfig(t, filepath.Join(repo, "devenv/docker/ha_test/docker-compose.yaml"))
		requireSafeMySQL(t, "ha_test", cfg.Services["db"].Image)
	})

	t.Run("ha-test-unified-alerting", func(t *testing.T) {
		cfg := composeFileConfig(t, filepath.Join(repo, "devenv/docker/ha-test-unified-alerting/docker-compose.yaml"))
		requireSafeMySQL(t, "ha-test-unified-alerting", cfg.Services["db"].Image)
	})

	t.Run("unified storage readme", func(t *testing.T) {
		body, err := os.ReadFile(filepath.Join(repo, "pkg/storage/unified/README.md"))
		if err != nil {
			t.Fatal(err)
		}
		images := regexp.MustCompile(`\bmysql:\d+\.\d+\.\d+(?:-[\w.]+)?`).FindAll(body, -1)
		for _, image := range images {
			requireSafeMySQL(t, "pkg/storage/unified/README.md", string(image))
		}
	})
}

func TestFixedMySQLVersionsAreOutsideCVE202622017(t *testing.T) {
	safe := []string{"mysql:8.0.46", "mysql:8.4.9", "mysql:9.6.1", "mysql:9.7.0"}
	for _, image := range safe {
		affected, err := mysqlServerAffected(image)
		if err != nil {
			t.Errorf("%s: %v", image, err)
		}
		if affected {
			t.Errorf("%s was classified as affected", image)
		}
	}
	affectedImages := []string{"mysql:8.0.0", "mysql:8.0.32", "mysql:8.0.45", "mysql:8.4.0", "mysql:8.4.8", "mysql:9.0.0", "mysql:9.6.0"}
	for _, image := range affectedImages {
		affected, err := mysqlServerAffected(image)
		if err != nil {
			t.Errorf("%s: %v", image, err)
		}
		if !affected {
			t.Errorf("%s was classified as fixed", image)
		}
	}
}

func requireSafeMySQL(t *testing.T, name, image string) {
	t.Helper()
	affected, err := mysqlServerAffected(image)
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return
	}
	if affected {
		t.Errorf("%s resolves %s, inside MySQL Server ranges affected by CVE-2026-22017 (8.0.0-8.0.45, 8.4.0-8.4.8, 9.0.0-9.6.0)", name, image)
	}
}

func mysqlServerAffected(image string) (bool, error) {
	tag := image
	if i := strings.LastIndex(tag, ":"); i >= 0 {
		tag = tag[i+1:]
	}
	tag = strings.SplitN(tag, "-", 2)[0]
	parts := strings.Split(tag, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("MySQL image %q is not a major.minor.patch pin", image)
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false, fmt.Errorf("MySQL image %q is not a numeric version", image)
	}
	switch {
	case major == 8 && minor == 0 && patch <= 45:
		return true, nil
	case major == 8 && minor == 4 && patch <= 8:
		return true, nil
	case major == 9 && (minor < 6 || (minor == 6 && patch == 0)):
		return true, nil
	default:
		return false, nil
	}
}

type composeService struct {
	Image string `json:"image"`
	Build *struct {
		Args map[string]string `json:"args"`
	} `json:"build"`
}

type composeFile struct {
	Services map[string]composeService `json:"services"`
}

func composeConfig(t *testing.T, dir string, env []string) composeFile {
	t.Helper()
	return decodeCompose(t, runCompose(t, dir, env, "config", "--format", "json"))
}

func composeFileConfig(t *testing.T, file string) composeFile {
	t.Helper()
	return decodeCompose(t, runCompose(t, filepath.Dir(file), nil, "-f", file, "config", "--format", "json"))
}

func decodeCompose(t *testing.T, out []byte) composeFile {
	t.Helper()
	var cfg composeFile
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("decode compose config: %v", err)
	}
	return cfg
}

// mysqlTestsImage applies the build-arg value Compose resolved, or the
// Dockerfile ARG default when Compose did not pass one, to the FROM image.
// Substitution is the simple ${name} / $name form BuildKit uses for this file.
func mysqlTestsImage(t *testing.T, repo string, build *struct {
	Args map[string]string `json:"args"`
}) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repo, "devenv/docker/blocks/mysql_tests/Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]string{}
	from := ""
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "ARG "); ok && from == "" {
			key, val, _ := strings.Cut(rest, "=")
			args[strings.TrimSpace(key)] = val
			continue
		}
		if rest, ok := strings.CutPrefix(line, "FROM "); ok {
			from = strings.Fields(rest)[0]
			break
		}
	}
	if from == "" {
		t.Fatal("mysql_tests Dockerfile has no FROM")
	}
	if build != nil {
		for key, val := range build.Args {
			args[key] = val
		}
	}
	image, err := expandSimple(from, args)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func expandSimple(word string, env map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		if word[i] != '$' {
			b.WriteByte(word[i])
			continue
		}
		if i+1 >= len(word) {
			b.WriteByte('$')
			break
		}
		if word[i+1] == '{' {
			end := strings.IndexByte(word[i+2:], '}')
			if end < 0 {
				return "", fmt.Errorf("unclosed substitution in %q", word)
			}
			name := word[i+2 : i+2+end]
			if strings.ContainsAny(name, ":+-?#%") {
				return "", fmt.Errorf("unsupported substitution ${%s}", name)
			}
			val, ok := env[name]
			if !ok {
				return "", fmt.Errorf("unset substitution ${%s}", name)
			}
			b.WriteString(val)
			i += 2 + end
			continue
		}
		j := i + 1
		for j < len(word) && (word[j] == '_' || word[j] >= 'A' && word[j] <= 'Z' || word[j] >= 'a' && word[j] <= 'z' || word[j] >= '0' && word[j] <= '9') {
			j++
		}
		name := word[i+1 : j]
		if name == "" {
			b.WriteByte('$')
			continue
		}
		val, ok := env[name]
		if !ok {
			return "", fmt.Errorf("unset substitution $%s", name)
		}
		b.WriteString(val)
		i = j - 1
	}
	return b.String(), nil
}

func workflowMySQLVersions(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`mysql_version=(\d+\.\d+\.\d+)`).FindAllSubmatch(body, -1)
	var versions []string
	for _, match := range matches {
		versions = append(versions, string(match[1]))
	}
	return versions
}

func runCreateCompose(t *testing.T, devenv, block string) {
	t.Helper()
	cmd := exec.Command("./create_docker_compose.sh", block)
	cmd.Dir = devenv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("create_docker_compose.sh %s: %v\n%s", block, err, out)
	}
}

func runCompose(t *testing.T, dir string, env []string, args ...string) []byte {
	t.Helper()
	bin, prefix := findCompose(t)
	cmd := exec.Command(bin, append(prefix, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr = string(exitErr.Stderr)
		}
		t.Fatalf("compose %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return out
}

func findCompose(t *testing.T) (string, []string) {
	t.Helper()
	if bin, err := exec.LookPath("docker"); err == nil {
		probe := exec.Command(bin, "compose", "version")
		if err := probe.Run(); err == nil {
			return bin, []string{"compose"}
		}
	}
	if bin, err := exec.LookPath("docker-compose"); err == nil {
		return bin, nil
	}
	t.Fatal("docker compose or docker-compose is required to resolve the image the devenv starts")
	return "", nil
}

func copyDevenv(t *testing.T, repo string) string {
	t.Helper()
	dst := t.TempDir()
	cmd := exec.Command("cp", "-a", filepath.Join(repo, "devenv")+"/.", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copy devenv: %v\n%s", err, out)
	}
	return dst
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
