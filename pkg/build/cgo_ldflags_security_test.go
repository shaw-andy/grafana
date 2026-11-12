package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The Go toolchain selected by this module must reject #cgo LDFLAGS that the
// compiler driver recombines and that the Apple linker then uses to dlopen an
// attacker-chosen library. Rejection has to happen before the compiler driver
// is invoked with those arguments.
func TestCgoLDFLAGSRejectsLinkerCodeLoadingFlags(t *testing.T) {
	t.Parallel()

	// The path ends in .dylib so it matches the direct-linker-input allow
	// pattern. It is empty so a missed check cannot hand the driver a plugin.
	lib := filepath.Join(t.TempDir(), "payload.dylib")
	if err := os.WriteFile(lib, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"-l to_library " + lib,
		"-lazy_library " + lib,
		"-lazy_framework " + lib,
		"-load_hidden " + lib,
		"-library " + lib,
		"-library=" + lib,
		"-library-path " + lib,
		"-library-path=" + lib,
	}
	for _, ldflags := range cases {
		t.Run(ldflags, func(t *testing.T) {
			t.Parallel()
			out, mark, err := buildCgo(t, ldflags)
			if err == nil {
				t.Fatalf("build succeeded with #cgo LDFLAGS %q\n%s", ldflags, out)
			}
			if strings.TrimSpace(mark) != "" {
				t.Fatalf("compiler driver was invoked with rejected linker flags before the build failed:\n%s\nbuild output:\n%s", mark, out)
			}
			if !strings.Contains(out, "invalid flag in #cgo LDFLAGS") {
				t.Fatalf("build failed without rejecting #cgo LDFLAGS %q:\n%s", ldflags, out)
			}
		})
	}
}

// Ordinary linker flags must keep working, so a fix cannot be "reject every #cgo LDFLAGS".
func TestCgoLDFLAGSAllowsOrdinaryLinkerFlag(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is not installed")
	}
	out, mark, err := buildCgo(t, "-pthread")
	if err != nil {
		t.Fatalf("ordinary #cgo LDFLAGS -pthread was rejected: %v\n%s", err, out)
	}
	if strings.TrimSpace(mark) != "" {
		t.Fatalf("ordinary link recorded a forbidden flag:\n%s", mark)
	}
}

func buildCgo(t *testing.T, ldflags string) (output, marker string, err error) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cc.log")
	markPath := filepath.Join(dir, "danger")
	cc := filepath.Join(dir, "cc-wrap")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$CC_LOG"
for arg in "$@"; do
  case "$arg" in
    to_library|-lazy_library|-lazy_framework|-load_hidden|-library|-library-path|-lto_library|-library=*|-library-path=*)
      printf '%s\n' "$arg" >> "$DANGER_MARK"
      exit 42
      ;;
  esac
done
exec gcc "$@"
`
	if err := os.WriteFile(cc, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package main\n\n/*\n#cgo LDFLAGS: " + ldflags + "\n\nint add(int a, int b) { return a + b; }\n*/\nimport \"C\"\nimport \"fmt\"\nfunc main() { fmt.Println(C.add(1, 2)) }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// Minimum language version only. The running toolchain is kept via GOTOOLCHAIN=local.
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/cgoprobe\n\ngo 1.26.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBin, "build", "-o", filepath.Join(dir, "out"), ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=1",
		"CC="+cc,
		"CC_LOG="+logPath,
		"DANGER_MARK="+markPath,
	)
	out, err := cmd.CombinedOutput()
	marked, _ := os.ReadFile(markPath)
	return string(out), string(marked), err
}
