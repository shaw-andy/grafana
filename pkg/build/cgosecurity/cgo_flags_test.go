package cgosecurity

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// These tests build a cgo package with the #cgo flags Go 1.26.6 still allows.
// They fail while that toolchain accepts the flags. The -target cases also
// fail if Clang runs a helper from the package directory: that happens before
// cmd/go reports the link error, so a non-empty marker is a failure even when
// the build exits non-zero. They pass once the toolchain rejects the flags
// before the compiler or linker is started.

func TestCgoMaliciousFlagsRejected(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		directive string
		flags     func(dir string) string
		cc        string
	}{
		{name: "ldflags-target-clang", directive: "LDFLAGS", cc: "clang", flags: func(string) string { return "-target x86_64-sie-ps4" }},
		{name: "cflags-target-clang", directive: "CFLAGS", cc: "clang", flags: func(string) string { return "-target x86_64-sie-ps4" }},
		{name: "cppflags-target-clang", directive: "CPPFLAGS", cc: "clang", flags: func(string) string { return "-target x86_64-sie-ps4" }},
		{name: "cxxflags-target-clang", directive: "CXXFLAGS", cc: "clang", flags: func(string) string { return "-target x86_64-sie-ps4" }},
		{name: "fflags-target-clang", directive: "FFLAGS", cc: "clang", flags: func(string) string { return "-target x86_64-sie-ps4" }},
		{name: "ldflags-target-default-cc", directive: "LDFLAGS", flags: func(string) string { return "-target x86_64-sie-ps4" }},
		{name: "cflags-sysroot-joined", directive: "CFLAGS", flags: sysrootJoined},
		{name: "cflags-sysroot-split", directive: "CFLAGS", flags: sysrootSplit},
		{name: "ldflags-sysroot-split", directive: "LDFLAGS", flags: sysrootSplit},
		{name: "cppflags-sysroot-joined", directive: "CPPFLAGS", flags: sysrootJoined},
		{name: "cxxflags-sysroot-joined", directive: "CXXFLAGS", flags: sysrootJoined},
		{name: "fflags-sysroot-joined", directive: "FFLAGS", flags: sysrootJoined},
		{name: "ldflags-sysroot-fopenmp", directive: "LDFLAGS", flags: func(dir string) string { return sysrootSplit(dir) + " -fopenmp" }},
		{name: "cflags-isysroot-file", directive: "CFLAGS", flags: func(dir string) string { return "-isysroot " + linkScript(dir) }},
		{name: "ldflags-isysroot-file", directive: "LDFLAGS", flags: func(dir string) string { return "-isysroot " + linkScript(dir) }},
		{name: "ldflags-syslibroot-comma", directive: "LDFLAGS", flags: func(dir string) string { return "-Wl,-syslibroot," + linkScript(dir) }},
		{name: "ldflags-syslibroot-equal", directive: "LDFLAGS", flags: func(dir string) string { return "-Wl,-syslibroot=" + linkScript(dir) }},
		{name: "cflags-x-ada", directive: "CFLAGS", flags: func(string) string { return "-x ada" }},
		{name: "cflags-x-ada-joined", directive: "CFLAGS", flags: func(string) string { return "-xada" }},
		{name: "cflags-x-none", directive: "CFLAGS", flags: func(string) string { return "-x none" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			marker, output, err := buildMaliciousCgo(t, tc.directive, tc.flags, tc.cc)
			if st, statErr := os.Stat(marker); statErr == nil && st.Size() > 0 {
				t.Fatalf("build executed a helper while applying #cgo %s\n%s", tc.directive, output)
			}
			if err == nil {
				t.Fatalf("go build accepted #cgo %s", tc.directive)
			}
			if !bytes.Contains(output, []byte("invalid flag")) {
				t.Fatalf("go build did not reject #cgo %s\n%s", tc.directive, output)
			}
		})
	}
}

func TestGoToolchainPinAtLeast12611(t *testing.T) {
	root := moduleRoot(t)
	var offenders []string

	out, err := exec.Command("go", "version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if v := goVersionFromOutput(string(out)); vulnerable126(v) {
		offenders = append(offenders, "running toolchain "+v)
	}

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "public", "data":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		switch d.Name() {
		case "go.mod", "go.work":
			offenders = append(offenders, pinnedGoLines(root, path)...)
		case "Dockerfile":
			text := string(mustRead(t, path))
			for _, h := range regexp.MustCompile(`golang:(1\.26\.\d+)`).FindAllStringSubmatch(text, -1) {
				if vulnerable126(h[1]) {
					offenders = append(offenders, rel+" "+h[0])
				}
			}
		case "Makefile":
			if rel != "Makefile" {
				return nil
			}
			text := string(mustRead(t, path))
			if m := regexp.MustCompile(`(?m)^GO_VERSION\s*=\s*(\S+)`).FindStringSubmatch(text); m != nil && vulnerable126(m[1]) {
				offenders = append(offenders, "Makefile GO_VERSION="+m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("Go toolchain still in the range fixed by 1.26.11:\n%s", strings.Join(offenders, "\n"))
	}
}

func pinnedGoLines(root, path string) []string {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "go ") {
			continue
		}
		ver := strings.TrimPrefix(line, "go ")
		if vulnerable126(ver) {
			rel, _ := filepath.Rel(root, path)
			out = append(out, rel+": "+line)
		}
	}
	return out
}

func sysrootJoined(dir string) string {
	return "--sysroot=" + filepath.Join(dir, "sysroot")
}

func sysrootSplit(dir string) string {
	return "--sysroot " + filepath.Join(dir, "sysroot")
}

func linkScript(dir string) string {
	return filepath.Join(dir, "link.ld")
}

func buildMaliciousCgo(t *testing.T, directive string, flags func(dir string) string, cc string) (marker string, output []byte, err error) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "executed")
	writeHelpers(t, dir, marker)
	plantSysroot(t, filepath.Join(dir, "sysroot"), marker)
	if err := os.WriteFile(linkScript(dir), []byte("OUTPUT_FORMAT(elf64-x86-64)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module malicious.example\n\ngo 1.26.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := fmt.Sprintf("package main\n\n/*\n#cgo %s: %s\nint cgo_security_anchor;\n*/\nimport \"C\"\n\nfunc main() {}\n", directive, flags(dir))
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "out"), ".")
	cmd.Dir = dir
	env := make([]string, 0, len(os.Environ())+6)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "CC=") || strings.HasPrefix(e, "GOTOOLCHAIN=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env,
		"CGO_ENABLED=1",
		"GOWORK=off",
		"GO111MODULE=on",
		"GOTOOLCHAIN=local",
		"PATH="+cleanPath(),
	)
	if cc != "" {
		env = append(env, "CC="+cc)
	}
	cmd.Env = env
	output, err = cmd.CombinedOutput()
	return marker, output, err
}

func writeHelpers(t *testing.T, dir, marker string) {
	t.Helper()
	script := "#!/bin/sh\nprintf 'ran %s\\n' \"$0\" >> " + strconv.Quote(marker) + "\nexit 0\n"
	for _, name := range []string{"orbis-ld", "prospero-lld", "llvm-spirv", "gnat1", "xcc"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func plantSysroot(t *testing.T, root, marker string) {
	t.Helper()
	payload := filepath.Join(root, "payload.sh")
	body := "#!/bin/sh\nprintf 'sysroot\\n' >> " + strconv.Quote(marker) + "\nexit 0\n"
	spec := "*linker:\n" + payload + "\n\n*link:\n" + payload + "\n"
	inst := filepath.Join(root, "usr", "lib", "gcc", "x86_64-linux-gnu", "99")
	dirs := []string{
		inst,
		filepath.Join(root, "usr", "lib", "gcc", "x86_64-linux-gnu", "13"),
		filepath.Join(root, "lib"),
		filepath.Join(root, "usr", "lib"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"specs", "libgomp.spec", "libsanitizer.spec"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(spec), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(payload, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inst, "ld"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, crt := range []string{"crtbegin.o", "crtbeginS.o", "crtendS.o"} {
		src := firstExisting("/usr/lib/gcc/x86_64-linux-gnu/14/"+crt, "/usr/lib/gcc/x86_64-linux-gnu/13/"+crt)
		if src == "" {
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(inst, crt), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func cleanPath() string {
	var parts []string
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == "" || p == "." {
			continue
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "/usr/bin:/bin"
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	dir := filepath.Dir(file)
	for {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && bytes.Contains(b, []byte("module github.com/grafana/grafana\n")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
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

func goVersionFromOutput(s string) string {
	for _, f := range strings.Fields(s) {
		if strings.HasPrefix(f, "go1.") {
			return strings.TrimPrefix(f, "go")
		}
	}
	return ""
}

func vulnerable126(ver string) bool {
	if ver == "" {
		return false
	}
	ver = strings.TrimPrefix(strings.Fields(ver)[0], "go")
	var maj, min, patch int
	if _, err := fmt.Sscanf(ver, "%d.%d.%d", &maj, &min, &patch); err != nil {
		return false
	}
	return maj == 1 && min == 26 && patch < 11
}
