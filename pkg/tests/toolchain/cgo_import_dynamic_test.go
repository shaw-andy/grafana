package toolchain

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise Go's external linker on a Windows target. A library
// name that reaches the linker as -l<name> can name a file outside the
// library search path. The toolchain under test is the one this module
// builds with.

func TestExternalLinkerDoesNotReceiveCgoImportDynamicTraversal(t *testing.T) {
	cases := []struct {
		name string
		lib  string
	}{
		{name: "dotdot-prefix", lib: "../sentinel.dll"},
		{name: "dotdot-middle", lib: "foo/../../sentinel.dll"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := fmt.Sprintf(`package main

import _ "unsafe"

//go:cgo_import_dynamic attacker attacker %q

//go:linkname attacker attacker
var attacker uintptr

func main() {
	if attacker != 0 {
		println(attacker)
	}
}
`, tc.lib)
			out := externalLink(t, map[string]string{"main.go": src}, "")
			assertLinkerDidNotReceive(t, out, linkerFlag(tc.lib))
		})
	}
}

func TestExternalLinkerDoesNotReceivePEImportedDLLName(t *testing.T) {
	// Each payload is the same length as the placeholder stored in the
	// import library ("sentinel.dll"), so the DLL name can be substituted
	// without shifting the PE bytes cmd/cgo parses.
	cases := []string{
		"../senti.dll",
		`-sentinel.dl`,
		"foo/bar.dllx",
		`@sentinel.dl`,
		`..\senti.dll`,
	}
	for _, dll := range cases {
		t.Run(dll, func(t *testing.T) {
			dir := t.TempDir()
			importGo := filepath.Join(dir, "_cgo_import.go")
			out, err := peDynimport(t, dir, dll, importGo)
			if err != nil {
				assertLinkerDidNotReceive(t, out, linkerFlag(dll))
				return
			}
			src := `package main

import _ "unsafe"

//go:linkname sentinelFunc SentinelFunc
var sentinelFunc uintptr

func main() {
	if sentinelFunc != 0 {
		println(sentinelFunc)
	}
}
`
			// cmd/go refuses to compile a user-supplied _cgo_ file, but it
			// does pass files it generated under that name straight to the
			// compiler. Append this dynimport output the same way.
			buildOut := externalLink(t, map[string]string{"main.go": src}, importGo)
			assertLinkerDidNotReceive(t, buildOut, linkerFlag(dll))
		})
	}
}

// linkerFlag is the external-linker argument cmd/link builds for a DLL name.
// cmd/cgo emits the name with %q and cmd/compile trims the quotes without
// interpreting Go escapes, so a backslash in the DLL name is doubled in the
// -l argument. The ".dll" suffix is stripped; any other suffix is kept.
func TestCgoObjectDoesNotCarryUnvalidatedPEDllName(t *testing.T) {
	dir := t.TempDir()
	const dll = "../senti.dll"
	craft := filepath.Join(dir, "craft")
	if err := os.Mkdir(craft, 0o755); err != nil {
		t.Fatal(err)
	}
	dynOut, err := peDynimport(t, craft, dll, filepath.Join(craft, "_cgo_import.go"))
	if err != nil {
		if isSetupFailure(dynOut + "\n" + err.Error()) {
			t.Fatalf("dynimport did not reach DLL-name validation: %v\n%s", err, dynOut)
		}
		return
	}
	if err := os.Rename(filepath.Join(craft, "libsentinel.a"), filepath.Join(dir, "libsentinel.a")); err != nil {
		t.Fatal(err)
	}
	// The generated _cgo_import.go is not part of this build. The import
	// library itself is the host object the external linker reads.
	src := `package main

/*
#cgo LDFLAGS: ./libsentinel.a
void SentinelFunc(void);
*/
import "C"

func main() { C.SentinelFunc() }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/linkflag\n\ngo "+moduleGoVersion(t)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "out.exe")
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Dir = dir
	cmd.Env = linkEnv(crossCC(t))
	out, err := cmd.CombinedOutput()
	if err == nil {
		body, rerr := os.ReadFile(exe)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if bytes.Contains(body, []byte(dll)) {
			t.Fatalf("linked binary imports %s", dll)
		}
		return
	}
	text := string(out)
	if strings.Contains(text, linkerFlag(dll)) || bytes.Contains(out, []byte(dll)) {
		t.Fatalf("external link consumed PE DLL name %s\n%s", dll, text)
	}
	if isSetupFailure(text) {
		t.Fatalf("build did not reach library-name validation:\n%s", text)
	}
}

func linkerFlag(dll string) string {
	quoted := fmt.Sprintf("%q", dll)
	inner := quoted[1 : len(quoted)-1]
	return "-l" + strings.TrimSuffix(inner, ".dll")
}

// assertLinkerDidNotReceive fails when the external linker was invoked with
// flag. A build that stops earlier, while refusing the name, is the fixed
// behavior. A failure to reach that choice (missing cross compiler, cgo
// disabled) is a test error.
func assertLinkerDidNotReceive(t *testing.T, output, flag string) {
	t.Helper()
	if strings.Contains(output, flag) {
		t.Fatalf("external linker received %s\n%s", flag, output)
	}
	if isSetupFailure(output) {
		t.Fatalf("build did not reach library-name validation:\n%s", output)
	}
}

func isSetupFailure(output string) bool {
	o := strings.ToLower(output)
	needles := []string{
		"cgo is not enabled",
		"executable file not found",
		"gcc: not found",
		"exec:",
		"no such file or directory",
		"cannot find package",
		"go.mod file not found",
	}
	for _, n := range needles {
		if strings.Contains(o, n) {
			// The vulnerable link fails because ld cannot find the unsafe
			// library. That message also contains "no such file or directory"
			// and is only a setup failure when the unsafe flag itself is absent.
			// Callers check the flag first.
			if n == "no such file or directory" && (strings.Contains(output, "cannot find -l") || strings.Contains(output, "# command-line-arguments")) {
				continue
			}
			return true
		}
	}
	return false
}

func externalLink(t *testing.T, files map[string]string, extraCompile string) string {
	t.Helper()
	cc := crossCC(t)
	dir := t.TempDir()
	ver := moduleGoVersion(t)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/linkflag\n\ngo "+ver+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"build", "-ldflags=-linkmode=external", "-o", filepath.Join(dir, "out.exe"), "."}
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = linkEnv(cc)
	if extraCompile != "" {
		script := filepath.Join(dir, "toolexec.sh")
		if err := os.WriteFile(script, []byte(toolexecScript), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd.Env = append(cmd.Env, "EXTRA_GOFILE="+extraCompile)
		cmd.Args = []string{cmd.Args[0], "build", "-toolexec=" + script, "-ldflags=-linkmode=external", "-o", filepath.Join(dir, "out.exe"), "."}
	}
	out, _ := cmd.CombinedOutput()
	return string(out)
}

const toolexecScript = `#!/bin/sh
tool=$1
shift
base=$(basename "$tool")
if [ "$base" = compile ]; then
	ismain=0
	haspack=0
	nextp=0
	for a in "$@"; do
		if [ "$nextp" = 1 ]; then
			if [ "$a" = main ]; then
				ismain=1
			fi
			nextp=0
			continue
		fi
		case "$a" in
		-p)
			nextp=1
			;;
		-p=main)
			ismain=1
			;;
		-pack)
			haspack=1
			;;
		esac
	done
	if [ "$ismain" = 1 ] && [ "$haspack" = 1 ]; then
		set -- "$@" "$EXTRA_GOFILE"
	fi
fi
exec "$tool" "$@"
`

func peDynimport(t *testing.T, dir, dll, dst string) (string, error) {
	t.Helper()
	cc := crossCC(t)
	dlltool := strings.TrimSuffix(cc, "gcc") + "dlltool"
	if _, err := exec.LookPath(dlltool); err != nil {
		t.Fatalf("dlltool %s: %v", dlltool, err)
	}
	const placeholder = "sentinel.dll"
	if len(dll) != len(placeholder) {
		t.Fatalf("payload %q length %d, want %d", dll, len(dll), len(placeholder))
	}
	def := filepath.Join(dir, "sentinel.def")
	if err := os.WriteFile(def, []byte("LIBRARY "+placeholder+"\nEXPORTS\n    SentinelFunc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(dir, "libsentinel.a")
	if out, err := exec.Command(dlltool, "-d", def, "-l", lib, "-m", "i386:x86-64").CombinedOutput(); err != nil {
		t.Fatalf("dlltool: %v\n%s", err, out)
	}
	blob, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(blob, []byte(placeholder)); n == 0 {
		t.Fatalf("import library has no %s to replace", placeholder)
	}
	blob = bytes.ReplaceAll(blob, []byte(placeholder), []byte(dll))
	if err := os.WriteFile(lib, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	useC := filepath.Join(dir, "use.c")
	if err := os.WriteFile(useC, []byte("__declspec(dllimport) void SentinelFunc(void);\nint main(void) { SentinelFunc(); return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	useObj := filepath.Join(dir, "use.o")
	useExe := filepath.Join(dir, "use.exe")
	if out, err := exec.Command(cc, "-c", useC, "-o", useObj).CombinedOutput(); err != nil {
		t.Fatalf("compile use.c: %v\n%s", err, out)
	}
	if out, err := exec.Command(cc, "-o", useExe, useObj, lib).CombinedOutput(); err != nil {
		t.Fatalf("link import library: %v\n%s", err, out)
	}
	cmd := exec.Command("go", "tool", "cgo", "-dynpackage", "main", "-dynimport", useExe, "-dynout", dst)
	cmd.Dir = dir
	cmd.Env = linkEnv(cc)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	body, rerr := os.ReadFile(dst)
	if rerr != nil {
		t.Fatal(rerr)
	}
	quoted := fmt.Sprintf("%q", dll)
	if !bytes.Contains(body, []byte(dll)) && !bytes.Contains(body, []byte(quoted)) {
		t.Fatalf("cgo -dynimport did not emit %s\n%s", quoted, body)
	}
	return string(out), nil
}

func crossCC(t *testing.T) string {
	t.Helper()
	cc := os.Getenv("CC")
	if cc == "" || !strings.Contains(cc, "mingw") {
		cc = "x86_64-w64-mingw32-gcc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Fatalf("windows cross compiler: %v", err)
	}
	return cc
}

func moduleGoVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOVERSION").CombinedOutput()
	if err != nil {
		t.Fatalf("go env GOVERSION: %v\n%s", err, out)
	}
	ver := strings.TrimPrefix(strings.TrimSpace(string(out)), "go")
	if ver == "" || strings.Contains(ver, " ") {
		t.Fatalf("unexpected GOVERSION %q", out)
	}
	return ver
}

func linkEnv(cc string) []string {
	env := os.Environ()
	drop := map[string]bool{"CC": true, "CGO_ENABLED": true, "GOOS": true, "GOARCH": true, "GO111MODULE": true}
	kept := env[:0]
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if drop[k] {
			continue
		}
		kept = append(kept, e)
	}
	return append(kept,
		"CC="+cc,
		"CGO_ENABLED=1",
		"GOOS=windows",
		"GOARCH=amd64",
		"GO111MODULE=on",
	)
}
