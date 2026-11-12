package toolchainsec

// These tests exercise cmd/go's handling of linker inputs with the toolchain
// selected by the repository go.mod. They fail while that toolchain passes a
// crafted .syso file, a direct #cgo LDFLAGS object, or a library from a -L
// directory through to the external linker, and they pass once the toolchain
// rejects that input first.
//
// A non-zero build status is not enough. On the vulnerable toolchain the
// external linker evaluates a GNU ld script (and, for an LTO object, runs
// lto-wrapper) before the link fails or the build succeeds. The assertions
// below are on that use, so a change that only inspects the file and then
// still hands the same path to the linker does not pass.
//
// Not covered here, because this host's external linker is GNU ld on Linux:
// PE/COFF .drectve directives as interpreted by the Windows linker, Mach-O
// LC_LINKER_OPTION commands as interpreted by the Darwin linker, and LLVM
// bitcode sections (.llvmbc, .llvm.lto) rather than the GCC .gnu.lto_ sections
// produced below. Direct linker inputs with the other allowlisted suffixes
// (.obj, .dll, .dylib, .lib, .tbd) share the same #cgo LDFLAGS check as the
// .o, .so, and .a cases.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const linkerScript = "ASSERT(0, \"LINKER_SCRIPT_REACHED\")\n"

const ccWrapScript = `#!/bin/sh
printf '%s\n' "$*" >> "$CCLOG"
echo "$*" | grep -q 'payload.syso' || exec /usr/bin/gcc "$@"
echo "$*" | grep -q ' -c ' && exec /usr/bin/gcc "$@"
/usr/bin/gcc -v "$@" >>"$CCLOG" 2>&1
exit $?
`

func TestLinkerInputsRejectedBeforeUse(t *testing.T) {
	t.Run("syso in main package", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "sysomain")
		writeFile(t, filepath.Join(dir, "main.go"), "package main\nfunc main() {}\n")
		writeFile(t, filepath.Join(dir, "payload.syso"), linkerScript)
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("syso in dependency", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "sysodep")
		writeFile(t, filepath.Join(dir, "evil", "evil.go"), "package evil\n")
		writeFile(t, filepath.Join(dir, "evil", "payload.syso"), linkerScript)
		writeFile(t, filepath.Join(dir, "main.go"), "package main\nimport _ \"example.com/sysodep/evil\"\nfunc main() {}\n")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo direct object", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgoobj")
		obj := filepath.Join(dir, "evil.o")
		writeFile(t, obj, linkerScript)
		writeCgo(t, dir, obj)
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo direct shared library", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgoso")
		lib := filepath.Join(dir, "libevil.so")
		writeFile(t, lib, linkerScript)
		writeCgo(t, dir, lib)
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo direct archive", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgoa")
		lib := filepath.Join(dir, "evil.a")
		writeFile(t, lib, linkerScript)
		writeCgo(t, dir, lib)
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo library search directory shared object", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgolibso")
		libdir := filepath.Join(dir, "libdir")
		writeFile(t, filepath.Join(libdir, "libfoo.so"), linkerScript)
		writeCgo(t, dir, "-L"+libdir+" -lfoo")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo library search directory archive", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgoliba")
		libdir := filepath.Join(dir, "libdir")
		writeFile(t, filepath.Join(libdir, "libfoo.a"), linkerScript)
		writeCgo(t, dir, "-L"+libdir+" -lfoo")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo exact library name", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgocolon")
		libdir := filepath.Join(dir, "libdir")
		writeFile(t, filepath.Join(libdir, "evil.o"), linkerScript)
		writeCgo(t, dir, "-L"+libdir+" -l:evil.o")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo exact library name in subdirectory", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgocolonpath")
		libdir := filepath.Join(dir, "libdir")
		writeFile(t, filepath.Join(libdir, "sub", "evil.o"), linkerScript)
		writeCgo(t, dir, "-L"+libdir+" -l:sub/evil.o")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo library name with path separator", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgoslash")
		libdir := filepath.Join(dir, "weird")
		writeFile(t, filepath.Join(libdir, "libnested", "bar.so"), linkerScript)
		writeCgo(t, dir, "-L"+libdir+" -lnested/bar")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo library name with equals", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgoeq")
		libdir := filepath.Join(dir, "libdir")
		writeFile(t, filepath.Join(libdir, "libfoo=bar.so"), linkerScript)
		writeCgo(t, dir, "-L"+libdir+" -lfoo=bar")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo exact library name with equals", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgocoloneq")
		libdir := filepath.Join(dir, "libdir")
		writeFile(t, filepath.Join(libdir, "evil=x.o"), linkerScript)
		writeCgo(t, dir, "-L"+libdir+" -l:evil=x.o")
		assertLinkerInputRejected(t, dir, "")
	})

	t.Run("cgo gcc lto object", func(t *testing.T) {
		t.Parallel()
		dir := newModule(t, "cgolto")
		obj := filepath.Join(dir, "payload.syso")
		cmd := exec.Command("/usr/bin/gcc", "-flto", "-fno-fat-lto-objects", "-c", "-x", "c", "-o", obj, "-")
		cmd.Stdin = strings.NewReader("int lto_anchor(void){return 1;}\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generating LTO object: %v\n%s", err, out)
		}
		writeFile(t, filepath.Join(dir, "main.go"), "package main\nimport \"C\"\nfunc main() {}\n")
		logPath := filepath.Join(dir, "cc.log")
		wrap := filepath.Join(dir, "ccwrap")
		writeFile(t, wrap, ccWrapScript)
		if err := os.Chmod(wrap, 0o755); err != nil {
			t.Fatal(err)
		}
		assertLinkerInputRejected(t, dir, "CC="+wrap, "CCLOG="+logPath)
	})
}

func assertLinkerInputRejected(t *testing.T, dir string, extraEnv ...string) {
	t.Helper()
	outPath := filepath.Join(dir, "out")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", outPath, ".")
	cmd.Dir = dir
	cmd.Env = goBuildEnv(extraEnv...)
	out, err := cmd.CombinedOutput()
	combined := string(out)
	if log, readErr := os.ReadFile(filepath.Join(dir, "cc.log")); readErr == nil {
		combined += "\n" + string(log)
	}
	if strings.Contains(combined, "LINKER_SCRIPT_REACHED") {
		t.Fatalf("external linker evaluated a linker script\n%s", combined)
	}
	if strings.Contains(combined, "lto-wrapper") || strings.Contains(combined, "liblto_plugin") {
		t.Fatalf("external linker loaded an LTO plugin for the crafted object\n%s", combined)
	}
	if err == nil {
		t.Fatalf("build succeeded; crafted linker input was accepted\n%s", combined)
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Fatalf("linker wrote %s before the build failed\n%s", outPath, combined)
	}
	for _, marker := range []string{
		"unrecognized binary format",
		"invalid linker input file",
		"invalid flag in #cgo LDFLAGS",
		"disallowed LTO section",
	} {
		if strings.Contains(combined, marker) {
			return
		}
	}
	t.Fatalf("build failed without rejecting the linker input\n%s", combined)
}

func newModule(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "mod", "init", "example.com/"+name)
	cmd.Dir = dir
	cmd.Env = goBuildEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod init: %v\n%s", err, out)
	}
	return dir
}

func writeCgo(t *testing.T, dir, ldflags string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n/*\n#cgo LDFLAGS: "+ldflags+"\n*/\nimport \"C\"\nfunc main() {}\n")
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func goBuildEnv(extra ...string) []string {
	drop := map[string]bool{
		"GOTOOLCHAIN": true,
		"CGO_ENABLED": true,
		"GOFLAGS":     true,
		"CC":          true,
		"CCLOG":       true,
	}
	env := make([]string, 0, len(os.Environ())+len(extra)+3)
	for _, e := range os.Environ() {
		key, _, ok := strings.Cut(e, "=")
		if ok && drop[key] {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "GOTOOLCHAIN=local", "CGO_ENABLED=1", "GOFLAGS=")
	return append(env, extra...)
}
