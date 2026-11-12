package models_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The Go toolchain selected by the root go.mod must refuse unsafe
// "#cgo pkg-config:" directives before it executes pkg-config, and it must
// treat -flto returned by pkg-config --cflags as incompatible with internal
// linking. These tests run the toolchain that compiled them (runtime.GOROOT).

const probePC = `prefix=/usr
libdir=${prefix}/lib
Name: libfoo
Version: 1
Description: probe
Libs: -L${libdir} -lfoo
Cflags: -I${prefix}/include
`

func TestUnsafeCgoPkgConfigDirectivesAreRejectedBeforePkgConfigRuns(t *testing.T) {
	goBin := toolchainGo(t)
	pkgConfig, err := exec.LookPath("pkg-config")
	if err != nil {
		t.Fatalf("pkg-config is required to observe the toolchain's pkg-config invocation: %v", err)
	}

	root := t.TempDir()
	mod := filepath.Join(root, "mod")
	pcs := filepath.Join(mod, "pcs")
	if err := os.MkdirAll(filepath.Join(mod, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pcs, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "libfoo.pc"),
		filepath.Join(mod, "libfoo.pc"),
		filepath.Join(mod, "nested", "libfoo.pc"),
		filepath.Join(pcs, "libfoo.pc"),
	} {
		if err := os.WriteFile(path, []byte(probePC), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// pkgconf treats the --personality= argument as a filesystem path first.
	personality := "Triplet: injected\nDefaultSearchPaths: /tmp/injected-personality\n"
	if err := os.WriteFile(filepath.Join(mod, "filename"), []byte(personality), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mod, "triplet"), []byte(personality), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		directive string
	}{
		{name: "with-path", directive: "--with-path=" + pcs + " libfoo"},
		{name: "personality-filename", directive: "--personality=filename libfoo"},
		{name: "personality-triplet", directive: "--personality=triplet libfoo"},
		{name: "define-variable-dollar", directive: "--define-variable=prefix=$SYSROOT libfoo.pc"},
		{name: "define-variable-equals", directive: "--define-variable=prefix==/opt libfoo.pc"},
		{name: "package-pc-suffix", directive: "libfoo.pc"},
		{name: "package-dot-slash-pc", directive: "./libfoo.pc"},
		{name: "package-path-separator", directive: "nested/libfoo.pc"},
		{name: "package-dotdot", directive: "../libfoo.pc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			modCopy := cloneProbeModule(t, root)
			marker := filepath.Join(t.TempDir(), "pkg-config-invoked")
			wrapper := writePkgConfigWrapper(t, marker, pkgConfig)
			log, buildErr := buildProbe(t, goBin, modCopy, tc.directive, []string{"PKG_CONFIG=" + wrapper})
			invoked := false
			if st, err := os.Stat(marker); err == nil && st.Mode().IsRegular() {
				invoked = true
			}
			if invoked {
				t.Fatalf("pkg-config ran for %q before the toolchain rejected it\n%s", tc.directive, relevantLog(log))
			}
			if buildErr == nil || !pkgConfigRejected(log) {
				t.Fatalf("toolchain accepted %q (err=%v); want a pkg-config flag or package-name rejection before exec\n%s", tc.directive, buildErr, relevantLog(log))
			}
		})
	}
}

func TestCgoPkgConfigCflagsFltoForcesExternalLink(t *testing.T) {
	t.Parallel()
	goBin := toolchainGo(t)
	pkgConfig, err := exec.LookPath("pkg-config")
	if err != nil {
		t.Fatalf("pkg-config is required: %v", err)
	}
	mod := t.TempDir()
	pcDir := filepath.Join(mod, "pc")
	if err := os.MkdirAll(pcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pc := "Name: libfoo\nVersion: 1\nDescription: probe\nCflags: -flto\n"
	if err := os.WriteFile(filepath.Join(pcDir, "libfoo.pc"), []byte(pc), 0o644); err != nil {
		t.Fatal(err)
	}
	log, buildErr := buildProbe(t, goBin, mod, "libfoo", []string{
		"PKG_CONFIG=" + pkgConfig,
		"PKG_CONFIG_PATH=" + pcDir,
	})
	if buildErr != nil {
		t.Fatalf("build failed before the internal-link decision: %v\n%s", buildErr, relevantLog(log))
	}
	if !strings.Contains(log, "-flto") {
		t.Fatalf("pkg-config Cflags -flto did not reach the compiler command\n%s", relevantLog(log))
	}
	if !workDirHasPreferlinkext(log) {
		t.Fatalf("pkg-config --cflags -flto was compiled without forcing external linking (preferlinkext missing)\n%s", relevantLog(log))
	}
}

func TestCgoCFLAGSFltoForcesExternalLink(t *testing.T) {
	t.Parallel()
	goBin := toolchainGo(t)
	mod := t.TempDir()
	log, buildErr := buildProbeSource(t, goBin, mod, cflagsProbeSource(), nil)
	if buildErr != nil {
		t.Fatalf("build failed: %v\n%s", buildErr, relevantLog(log))
	}
	if !workDirHasPreferlinkext(log) {
		t.Fatalf("direct #cgo CFLAGS: -flto did not emit preferlinkext\n%s", relevantLog(log))
	}
}

func toolchainGo(t *testing.T) string {
	t.Helper()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		t.Fatalf("toolchain go binary %s: %v", goBin, err)
	}
	return goBin
}

func writePkgConfigWrapper(t *testing.T, marker, pkgConfig string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg-config")
	script := fmt.Sprintf("#!/bin/sh\n: > %s\nexec %s \"$@\"\n", shellQuote(marker), shellQuote(pkgConfig))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func cloneProbeModule(t *testing.T, root string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dst, "mod")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func buildProbe(t *testing.T, goBin, mod, directive string, extraEnv []string) (string, error) {
	t.Helper()
	return buildProbeSource(t, goBin, mod, pkgConfigProbeSource(directive), extraEnv)
}

func buildProbeSource(t *testing.T, goBin, mod, source string, extraEnv []string) (string, error) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(mod, "go.mod"), []byte("module example.com/pkgconfigprobe\n\ngo 1.26.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mod, "p.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	cmd := exec.Command(goBin, "build", "-x", "-work", "-o", filepath.Join(mod, "probe.a"), ".")
	cmd.Dir = mod
	cmd.Env = append(cleanBuildEnv(), extraEnv...)
	cmd.Env = append(cmd.Env,
		"GOROOT="+runtime.GOROOT(),
		"GOCACHE="+cache,
		"GOTMPDIR="+cache,
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=1",
		"CC=gcc",
		"GO111MODULE=on",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func cleanBuildEnv() []string {
	keep := []string{"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT"}
	env := make([]string, 0, len(keep))
	for _, key := range keep {
		if v, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+v)
		}
	}
	return env
}

func pkgConfigProbeSource(directive string) string {
	return "package p\n\n/*\n#cgo pkg-config: " + directive + "\n*/\nimport \"C\"\n\nfunc F() {}\n"
}

func cflagsProbeSource() string {
	return "package p\n\n/*\n#cgo CFLAGS: -flto\n*/\nimport \"C\"\n\nfunc F() {}\n"
}

func pkgConfigRejected(log string) bool {
	return strings.Contains(log, "invalid flag in pkg-config:") ||
		strings.Contains(log, "invalid pkg-config package name:")
}

func relevantLog(log string) string {
	var b strings.Builder
	for _, line := range strings.Split(log, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "WORK=") ||
			strings.Contains(trim, "pkg-config") ||
			strings.Contains(trim, "gcc ") ||
			strings.Contains(trim, "-flto") ||
			strings.Contains(trim, "-L") ||
			strings.Contains(trim, "invalid") ||
			strings.Contains(trim, "malformed") ||
			strings.Contains(trim, "cgo ") {
			b.WriteString(trim)
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		return log
	}
	return b.String()
}

func workDirHasPreferlinkext(log string) bool {
	work := ""
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "WORK=") {
			work = strings.TrimPrefix(line, "WORK=")
			break
		}
	}
	if work == "" {
		return false
	}
	found := false
	_ = filepath.Walk(work, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "preferlinkext" {
			found = true
			return fmt.Errorf("found")
		}
		return nil
	})
	return found
}
