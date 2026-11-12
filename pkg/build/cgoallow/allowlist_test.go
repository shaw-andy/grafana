package cgoallow_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCgoGenAndGnatFlagsRejected builds a small cgo package whose #cgo
// directives carry Clang -gen-cdb-fragment-path and GCC -gnatO. Go 1.26.6's
// cmd/go allowlist treats both as ordinary -g debug flags, so the compiler
// still receives them. -gen-cdb-fragment-path consumes the next argument as
// an output directory. The argument is a single -I token whose first
// character after -I is a slash, which passes the allowlist and which
// makePathsAbsolute leaves unchanged because the remainder looks absolute.
// The compiler instead uses that whole token as a relative path, enters the
// package's "-I" directory, and walks ".." back out to an arbitrary directory.
//
// The build must be refused with an invalid-flag error, and it must not
// create that directory. These tests fail while the allowlist still matches
// the flags.
func TestCgoGenAndGnatFlagsRejected(t *testing.T) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		t.Fatalf("toolchain go binary: %v", err)
	}

	cc, cxx := compilerPair(t)

	cases := []struct {
		name      string
		directive string // "ESCAPE" is replaced with the -I/../ traversal token
		files     map[string]string
		pkgconfig *pcFile
	}{
		{
			name:      "cflags-gen",
			directive: "#cgo CFLAGS: -gen-cdb-fragment-path ESCAPE",
			files:     map[string]string{"x.c": "int x;\n"},
		},
		{
			name:      "cppflags-gen",
			directive: "#cgo CPPFLAGS: -gen-cdb-fragment-path ESCAPE",
			files:     map[string]string{"x.c": "int x;\n"},
		},
		{
			name:      "cxxflags-gen",
			directive: "#cgo CXXFLAGS: -gen-cdb-fragment-path ESCAPE",
			files:     map[string]string{"x.cpp": "int x;\n"},
		},
		{
			name:      "fflags-gen",
			directive: "#cgo FFLAGS: -gen-cdb-fragment-path ESCAPE",
			files:     map[string]string{"x.f": "      subroutine x\n      end\n"},
		},
		{
			name:      "cflags-gnatO",
			directive: "#cgo CFLAGS: -gnatO ESCAPE",
			files:     map[string]string{"x.c": "int x;\n"},
		},
		{
			name:      "ldflags-gnatO",
			directive: "#cgo LDFLAGS: -gnatO ./side.o",
			files:     map[string]string{"x.c": "int x;\n"},
		},
		{
			name:      "ldflags-gen",
			directive: "#cgo LDFLAGS: -gen-cdb-fragment-path ./side.o",
			files:     map[string]string{"x.c": "int x;\n"},
		},
		{
			name:      "pkgconfig-cflags-gen",
			directive: "#cgo pkg-config: foo",
			files:     map[string]string{"x.c": "int x;\n"},
			pkgconfig: &pcFile{cflags: "-gen-cdb-fragment-path ESCAPE", libs: "-lpthread"},
		},
		{
			name:      "pkgconfig-libs-gnatO",
			directive: "#cgo pkg-config: foo",
			files:     map[string]string{"x.c": "int x;\n"},
			pkgconfig: &pcFile{cflags: "-DFOO=1", libs: "-gnatO ./side.o"},
		},
		{
			name:      "pkgconfig-libs-gen",
			directive: "#cgo pkg-config: foo",
			files:     map[string]string{"x.c": "int x;\n"},
			pkgconfig: &pcFile{cflags: "-DFOO=1", libs: "-gen-cdb-fragment-path ./side.o"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pkgconfig != nil {
				if _, err := exec.LookPath("pkg-config"); err != nil {
					t.Skip("pkg-config is not installed")
				}
			}
			root := t.TempDir()
			pkgDir := filepath.Join(root, "p")
			outDir := filepath.Join(root, "outside")
			if err := os.MkdirAll(filepath.Join(pkgDir, "-I"), 0o755); err != nil {
				t.Fatal(err)
			}
			escape, err := traversalArg(pkgDir, outDir)
			if err != nil {
				t.Fatal(err)
			}
			directive := strings.ReplaceAll(tc.directive, "ESCAPE", escape)
			source := "package p\n\n/*\n" + directive + "\n*/\nimport \"C\"\n"
			if err := os.WriteFile(filepath.Join(pkgDir, "p.go"), []byte(source), 0o644); err != nil {
				t.Fatal(err)
			}
			for name, body := range tc.files {
				if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			goMod := "module cgoallowtest\n\ngo 1.26.6\n"
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0o644); err != nil {
				t.Fatal(err)
			}

			env := map[string]string{
				"GOTOOLCHAIN": "local",
				"CGO_ENABLED": "1",
				"CC":          cc,
				"CXX":         cxx,
				"GO111MODULE": "on",
			}
			if tc.pkgconfig != nil {
				pcDir := filepath.Join(root, "pc")
				if err := os.MkdirAll(pcDir, 0o755); err != nil {
					t.Fatal(err)
				}
				body := "Name: foo\nVersion: 1.0\nDescription: probe\nCflags: " +
					strings.ReplaceAll(tc.pkgconfig.cflags, "ESCAPE", escape) +
					"\nLibs: " + tc.pkgconfig.libs + "\n"
				if err := os.WriteFile(filepath.Join(pcDir, "foo.pc"), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				env["PKG_CONFIG_PATH"] = pcDir
			}

			cmd := exec.Command(goBin, "build", "./p")
			cmd.Dir = root
			cmd.Env = mergeEnv(env)
			out, err := cmd.CombinedOutput()
			written := writtenFiles(t, outDir)
			sideObject := filepath.Join(pkgDir, "side.o")
			if _, statErr := os.Stat(sideObject); statErr == nil {
				written = append(written, sideObject)
			}
			if len(written) > 0 {
				t.Fatalf("cgo build wrote files before refusing the flag:\n%v\n%s", written, out)
			}
			if err == nil {
				t.Fatalf("cgo build accepted %s\n%s", directive, out)
			}
			if !bytes.Contains(out, []byte("invalid flag")) {
				t.Fatalf("cgo build did not reject the flag\n%s", out)
			}
		})
	}
}

type pcFile struct {
	cflags string
	libs   string
}

// traversalArg is the single compiler argument that follows -gen-cdb-fragment-path
// or -gnatO. It matches the -I allowlist entry. From the package directory the
// compiler resolves it by entering "-I" and then applying the ".." components,
// which lands on outDir.
func traversalArg(pkgDir, outDir string) (string, error) {
	rel, err := filepath.Rel(filepath.Join(pkgDir, "-I"), outDir)
	if err != nil {
		return "", err
	}
	return "-I/" + filepath.ToSlash(rel), nil
}

func compilerPair(t *testing.T) (cc, cxx string) {
	t.Helper()
	cc = "gcc"
	if path, err := exec.LookPath("clang"); err == nil {
		cc = path
	}
	cxx = "g++"
	if path, err := exec.LookPath("clang++"); err == nil {
		cxx = path
	}
	return cc, cxx
}

func mergeEnv(overrides map[string]string) []string {
	var out []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, ok := overrides[key]; ok {
			continue
		}
		out = append(out, entry)
	}
	for key, value := range overrides {
		out = append(out, key+"="+value)
	}
	return out
}

func writtenFiles(t *testing.T, dir string) []string {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	if !info.IsDir() {
		return []string{dir}
	}
	var found []string
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir && !d.IsDir() {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Creating the directory is itself a write, even when it is still empty.
	if len(found) == 0 {
		return []string{dir}
	}
	return found
}
