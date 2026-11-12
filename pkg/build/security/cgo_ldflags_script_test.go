package security

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCgoLDFLAGSDoesNotInterpretLinkerScript builds a tiny cgo program whose
// #cgo LDFLAGS name a regular file. The file is a GNU ld script whose INPUT
// command names a sentinel that does not exist.
//
// The toolchain must reject those flags while checking #cgo LDFLAGS, before
// the host linker parses the file. A link that reports the sentinel means the
// script was interpreted. These tests fail on Go 1.26.6 and pass once the
// toolchain rejects the flags.
func TestCgoLDFLAGSDoesNotInterpretLinkerScript(t *testing.T) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go"+exeSuffix())
	if _, err := os.Stat(goBin); err != nil {
		t.Fatalf("go binary for the running toolchain: %v", err)
	}

	// Forms observed to reach the host linker under Go 1.26.6. $SCRIPT is the
	// absolute path of the linker script. A leading "!" writes that same script
	// to <module>/evilname or <module>/console so a bare filename can refer to it.
	cases := []struct {
		name    string
		ldflags string
	}{
		{name: "just-symbols-equals", ldflags: "-Wl,--just-symbols=$SCRIPT"},
		{name: "just-symbols-comma", ldflags: "-Wl,--just-symbols,$SCRIPT"},
		{name: "just-symbols-bare", ldflags: "-Wl,--just-symbols $SCRIPT"},
		{name: "just-symbols-wl-prefix", ldflags: "-Wl,--just-symbols -Wl,$SCRIPT"},
		{name: "r-comma", ldflags: "-Wl,-R,$SCRIPT"},
		{name: "r-bare", ldflags: "-Wl,-R $SCRIPT"},
		{name: "r-wl-prefix", ldflags: "-Wl,-R -Wl,$SCRIPT"},
		{name: "r-equals", ldflags: "-Wl,-R=$SCRIPT"},
		{name: "push-state-just-symbols", ldflags: "-Wl,--push-state,--just-symbols=$SCRIPT"},
		{name: "rpath-bare", ldflags: "-Wl,-rpath $SCRIPT"},
		{name: "undefined-bare", ldflags: "-Wl,-undefined $SCRIPT"},
		{name: "undefined-comma", ldflags: "-Wl,-undefined,$SCRIPT"},
		{name: "framework-absolute", ldflags: "-Wl,-framework,$SCRIPT"},
		{name: "framework-bare-filename", ldflags: "!-Wl,-framework evilname"},
		{name: "sectcreate-file", ldflags: "-Wl,-sectcreate,seg,sect,$SCRIPT"},
		{name: "warn-backrefs-exclude", ldflags: "-Wl,--warn-backrefs-exclude"},
		{name: "subsystem-console-file", ldflags: "!-Wl,-subsystem,console"},
		{name: "positional-so", ldflags: "$SCRIPT.so"},
		{name: "positional-o", ldflags: "$SCRIPT.o"},
		{name: "positional-a", ldflags: "$SCRIPT.a"},
		{name: "positional-dll", ldflags: "$SCRIPT.dll"},
		{name: "positional-dylib", ldflags: "$SCRIPT.dylib"},
		{name: "positional-tbd", ldflags: "$SCRIPT.tbd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sentinel := filepath.Join(dir, "cgo-ldscript-sentinel.o")
			scriptPath := filepath.Join(dir, "script.ld")
			scriptBody := "INPUT(" + sentinel + ")\n"
			if err := os.WriteFile(scriptPath, []byte(scriptBody), 0o644); err != nil {
				t.Fatal(err)
			}

			ldflags := tc.ldflags
			writeNamedScript := strings.HasPrefix(ldflags, "!")
			if writeNamedScript {
				ldflags = strings.TrimPrefix(ldflags, "!")
				for _, name := range []string{"evilname", "console"} {
					if strings.Contains(ldflags, name) {
						if err := os.WriteFile(filepath.Join(dir, name), []byte(scriptBody), 0o644); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			for _, ext := range []string{".so", ".o", ".a", ".dll", ".dylib", ".tbd"} {
				token := "$SCRIPT" + ext
				if strings.Contains(ldflags, token) {
					dest := scriptPath + ext
					if err := os.WriteFile(dest, []byte(scriptBody), 0o644); err != nil {
						t.Fatal(err)
					}
					ldflags = strings.ReplaceAll(ldflags, token, dest)
				}
			}
			ldflags = strings.ReplaceAll(ldflags, "$SCRIPT", scriptPath)

			src := fmt.Sprintf("package main\n\n/*\n#cgo LDFLAGS: %s\n*/\nimport \"C\"\n\nfunc main() {}\n", ldflags)
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/cgoflagprobe\n\ngo 1.26.6\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(goBin, "build", "-o", filepath.Join(dir, "out"), ".")
			cmd.Dir = dir
			cmd.Env = toolchainEnv()
			out, err := cmd.CombinedOutput()
			text := string(out)
			if _, statErr := os.Stat(sentinel); statErr == nil {
				t.Fatalf("linker created %s before refusing the flags:\n%s", sentinel, text)
			}
			if strings.Contains(text, "cgo-ldscript-sentinel.o") {
				t.Fatalf("host linker interpreted the script (sentinel was opened):\n%s", text)
			}
			if err == nil {
				t.Fatalf("go build accepted #cgo LDFLAGS %q", ldflags)
			}
			// Rejection has to come from the #cgo flag check. "running <cc>" is
			// cmd/link reporting that the host linker already executed.
			if strings.Contains(text, "running ") || !strings.Contains(text, "invalid ") {
				t.Fatalf("go build failed without rejecting the flags (%v):\n%s", err, text)
			}
		})
	}
}

func toolchainEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "CGO_") || strings.HasPrefix(e, "GOTOOLCHAIN=") {
			continue
		}
		env = append(env, e)
	}
	// local keeps the child on the toolchain that compiled this test, which is
	// the toolchain selected by the module that owns the test.
	env = append(env, "CGO_ENABLED=1", "GOTOOLCHAIN=local", "GO111MODULE=on")
	return env
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
