package toolchain

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// These tests exercise Go's handling of #cgo LDFLAGS values that contain a
// double quote. safeCgoName rejects a quote written in the directive itself
// (go/build/build.go), but makePathsAbsolute runs after that check and joins a
// relative -L argument with the package directory. A directory name containing
// a quote therefore becomes a linker argument. cmd/cgo writes it with
// strconv.Quote, and Go 1.26.6 parses the generated //go:cgo_ldflag line by
// trimming quote characters instead of unquoting it.
//
// The assertions below are the behavior after that parsing is fixed. On Go
// 1.26.6 they fail: the go command panics, and the external linker receives a
// path whose trailing quote was turned into a backslash.

func TestCgoLdflagEscapedQuoteDoesNotPanicGoCommand(t *testing.T) {
	dir := writeCgoPkg(t, "pq\"", `
package main

/*
#cgo LDFLAGS: -L.
#cgo LDFLAGS: -O2
int x;
*/
import "C"

func main() {}
`)

	out, err := goBuild(t, dir, false)
	if strings.Contains(out, "panic:") || strings.Contains(out, "index out of range") {
		t.Fatalf("go command panicked while building cgo package:\n%s", out)
	}
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
}

func TestCgoLdflagQuotedDirectoryReachesLinkerUnchanged(t *testing.T) {
	dir := writeCgoPkg(t, "rt\"", `
package main

/*
#cgo LDFLAGS: -L.
int x;
*/
import "C"

func main() {}
`)

	out, err := goBuild(t, dir, true)
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	args := hostLinkArgs(t, out)
	want := "-L" + dir
	for _, arg := range args {
		if arg == want {
			return
		}
	}
	var got []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-L") || strings.HasPrefix(arg, "-Wl,") {
			got = append(got, arg)
		}
	}
	t.Fatalf("external linker was not passed %q; linker flags: %#v\nfull host link: %s", want, got, hostLinkLine(out))
}

func writeCgoPkg(t *testing.T, name, source string) string {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module cgoldflagfixture\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func goBuild(t *testing.T, dir string, linkVerbose bool) (string, error) {
	t.Helper()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		t.Fatalf("toolchain go binary: %v", err)
	}
	cc, err := exec.Command(goBin, "env", "CC").CombinedOutput()
	if err != nil {
		t.Fatalf("go env CC: %v\n%s", err, cc)
	}
	compiler := strings.TrimSpace(string(cc))
	if compiler == "" {
		t.Skip("no C compiler")
	}
	if _, err := exec.LookPath(strings.Fields(compiler)[0]); err != nil {
		t.Skipf("C compiler %q not on PATH", compiler)
	}

	outPath := filepath.Join(t.TempDir(), "out")
	args := []string{"build", "-o", outPath}
	if linkVerbose {
		args = append(args, "-ldflags=-linkmode=external -v")
	}
	args = append(args, ".")
	cmd := exec.Command(goBin, args...)
	cmd.Dir = dir
	cmd.Env = toolchainEnv()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func toolchainEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		switch {
		case strings.HasPrefix(e, "GOTOOLCHAIN="),
			strings.HasPrefix(e, "CGO_ENABLED="),
			strings.HasPrefix(e, "CGO_LDFLAGS="),
			strings.HasPrefix(e, "CGO_LDFLAGS_ALLOW="),
			strings.HasPrefix(e, "CGO_LDFLAGS_DISALLOW="):
			continue
		default:
			env = append(env, e)
		}
	}
	return append(env,
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=1",
		"CGO_LDFLAGS=",
		"CGO_LDFLAGS_ALLOW=",
		"CGO_LDFLAGS_DISALLOW=",
	)
}

func hostLinkLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "host link:") {
			return line
		}
	}
	return ""
}

func hostLinkArgs(t *testing.T, out string) []string {
	t.Helper()
	line := hostLinkLine(out)
	if line == "" {
		t.Fatalf("build succeeded without a host link line:\n%s", out)
	}
	_, rest, ok := strings.Cut(line, "host link:")
	if !ok {
		t.Fatalf("host link line: %s", line)
	}
	rest = strings.TrimSpace(rest)
	var args []string
	for rest != "" {
		prefix, err := strconv.QuotedPrefix(rest)
		if err != nil {
			t.Fatalf("quoted linker arg in %q: %v", rest, err)
		}
		arg, err := strconv.Unquote(prefix)
		if err != nil {
			t.Fatalf("unquote %s: %v", prefix, err)
		}
		args = append(args, arg)
		rest = strings.TrimSpace(rest[len(prefix):])
	}
	return args
}
