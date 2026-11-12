package toolchaincheck

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// longSysoName is longer than the 16-byte archive member field. Go 1.26.6
// drops the ".syso" suffix when it truncates that field, and the linker
// then no longer treats the member as a .syso.
const longSysoName = "injected_flags.syso"

func TestDisguisedSysoDoesNotInjectDynamicLinker(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PT_INTERP observation is Linux ELF")
	}
	dir := t.TempDir()
	interpreter := filepath.Join(dir, "interpreter-marker")
	lib := "libsyso-import-marker.so"
	writeModule(t, dir, map[string][]byte{
		"main.go": []byte("package main\nfunc main() {}\n"),
		"crafted.syso": craftSyso(t, [][]string{
			{"cgo_import_dynamic", "_", "_", lib},
			{"cgo_dynamic_linker", interpreter},
		}),
	})

	bin := filepath.Join(dir, "out.bin")
	log := goBuild(t, dir, "-o", bin, ".")
	requireSysoPacked(t, log, "crafted.syso")
	rejectFingerprintMismatch(t, log)

	blob, err := os.ReadFile(bin)
	if err != nil {
		return
	}
	if bytes.Contains(blob, []byte(interpreter)) || bytes.Contains(blob, []byte(lib)) {
		t.Fatalf("cgo directives embedded in crafted.syso were applied to the linked binary")
	}
}

func TestDisguisedSysoDoesNotInjectLinkerFlag(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "link.map")
	flag := "-Wl,-Map," + mapPath
	writeModule(t, dir, map[string][]byte{
		"main.go":           []byte("package main\nfunc main() {}\n"),
		"crafted.syso":      craftSyso(t, [][]string{{"cgo_ldflag", flag}}),
		"unrecognized.syso": []byte("XXXX"),
	})

	log := goBuild(t, dir, "-o", filepath.Join(dir, "out.bin"), ".")
	requireSysoPacked(t, log, "crafted.syso")
	rejectFingerprintMismatch(t, log)
	if strings.Contains(log, flag) {
		t.Fatalf("cgo_ldflag from crafted.syso was passed to the external linker:\n%s", tail(log))
	}
	if _, err := os.Stat(mapPath); err == nil {
		t.Fatalf("external linker created %s from a cgo_ldflag embedded in crafted.syso", mapPath)
	}
}

func TestLongSysoNameDoesNotInjectLinkerFlag(t *testing.T) {
	if len(longSysoName) <= 16 {
		t.Fatal("fixture name must exceed the 16-byte archive member field")
	}
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "link.map")
	flag := "-Wl,-Map," + mapPath
	writeModule(t, dir, map[string][]byte{
		"main.go":           []byte("package main\nfunc main() {}\n"),
		longSysoName:        craftSyso(t, [][]string{{"cgo_ldflag", flag}}),
		"unrecognized.syso": []byte("XXXX"),
	})

	log := goBuild(t, dir, "-o", filepath.Join(dir, "out.bin"), ".")
	requireSysoPacked(t, log, longSysoName)
	rejectFingerprintMismatch(t, log)
	if strings.Contains(log, flag) {
		t.Fatalf("cgo_ldflag from %s was passed to the external linker after the archive name was truncated:\n%s", longSysoName, tail(log))
	}
	if _, err := os.Stat(mapPath); err == nil {
		t.Fatalf("external linker created %s from a cgo_ldflag embedded in %s", mapPath, longSysoName)
	}
}

func TestUnrecognizedSysoDoesNotForceExternalLink(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, map[string][]byte{
		"main.go":           []byte("package main\nfunc main() {}\n"),
		"unrecognized.syso": []byte("XXXX"),
	})

	log := goBuild(t, dir, "-o", filepath.Join(dir, "out.bin"), ".")
	requireSysoPacked(t, log, "unrecognized.syso")
	if strings.Contains(log, "running gcc") || strings.Contains(log, "running clang") {
		t.Fatalf("unrecognized .syso forced an external link:\n%s", tail(log))
	}
}

func TestCmdPackPreservesSysoSuffix(t *testing.T) {
	if len(longSysoName) <= 16 {
		t.Fatal("fixture name must exceed the 16-byte archive member field")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "uniq.go")
	if err := os.WriteFile(src, []byte("package uniq\nfunc Marker() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "uniq.a")
	if log, err := runGo(t, dir, "tool", "compile", "-p", "uniq", "-o", archive, src); err != nil {
		t.Fatalf("compile: %v\n%s", err, log)
	}
	payload := []byte("SYSO-PACK-MARKER")
	syso := filepath.Join(dir, longSysoName)
	if err := os.WriteFile(syso, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if log, err := runGo(t, dir, "tool", "pack", "r", archive, syso); err != nil {
		t.Fatalf("pack: %v\n%s", err, log)
	}
	name := memberNameContaining(t, mustRead(t, archive), payload)
	if !strings.HasSuffix(name, ".syso") {
		t.Fatalf("cmd/pack stored %s as archive member %q", longSysoName, name)
	}
}

func TestCmdGoPackPreservesSysoSuffix(t *testing.T) {
	if len(longSysoName) <= 16 {
		t.Fatal("fixture name must exceed the 16-byte archive member field")
	}
	dir := t.TempDir()
	payload := []byte("SYSO-GOPACK-MARKER")
	writeModule(t, dir, map[string][]byte{
		"main.go":    []byte("package main\nfunc main() {}\n"),
		longSysoName: payload,
	})
	log := goBuild(t, dir, "-work", "-o", filepath.Join(dir, "out.bin"), ".")
	requireSysoPacked(t, log, longSysoName)
	work := workDir(log)
	if work == "" {
		t.Fatalf("build log did not report WORK:\n%s", log)
	}
	t.Cleanup(func() { os.RemoveAll(work) })

	archive := findArchiveContaining(t, work, payload)
	name := memberNameContaining(t, mustRead(t, archive), payload)
	if !strings.HasSuffix(name, ".syso") {
		t.Fatalf("cmd/go stored %s as archive member %q in %s", longSysoName, name, archive)
	}
}

func craftSyso(t *testing.T, directives [][]string) []byte {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "uniq.go")
	if err := os.WriteFile(src, []byte("package uniq\nfunc Marker() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "uniq.a")
	if log, err := runGo(t, dir, "tool", "compile", "-p", "uniq", "-o", archive, src); err != nil {
		t.Fatalf("compile: %v\n%s", err, log)
	}
	obj := extractMember(t, mustRead(t, archive), "_go_.o")
	// A non-zero fingerprint that disagrees with the real package object
	// aborts the link before cgo directives already read from this member
	// are applied. Zero it so the directives reach the linker.
	obj = zeroObjectFingerprint(t, obj)

	bang := bytes.Index(obj, []byte("\n!\n"))
	if bang < 0 {
		t.Fatal("compiled object has no export terminator")
	}
	raw, err := json.Marshal(directives)
	if err != nil {
		t.Fatal(err)
	}
	section := []byte("\n$$\n\n$$\n\n\n$$  // cgo\n" + string(raw) + "\n\n$$\n\n")
	crafted := make([]byte, 0, len(obj)+len(section))
	crafted = append(crafted, obj[:bang]...)
	crafted = append(crafted, section...)
	crafted = append(crafted, obj[bang:]...)
	return crafted
}

func zeroObjectFingerprint(t *testing.T, obj []byte) []byte {
	t.Helper()
	bang := bytes.Index(obj, []byte("\n!\n"))
	if bang < 0 {
		t.Fatal("compiled object has no export terminator")
	}
	const magic = "\x00go120ld"
	at := bytes.Index(obj[bang:], []byte(magic))
	if at < 0 {
		t.Fatal("compiled object has no goobj magic")
	}
	fp := bang + at + len(magic)
	if fp+8 > len(obj) {
		t.Fatal("compiled object fingerprint is truncated")
	}
	out := append([]byte(nil), obj...)
	for i := 0; i < 8; i++ {
		out[fp+i] = 0
	}
	return out
}

func writeModule(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	mod := "module example.com/sysocheck\n\ngo 1.26.6\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func goBuild(t *testing.T, dir string, args ...string) string {
	t.Helper()
	log, err := runGo(t, dir, append([]string{"build", "-x"}, args...)...)
	if err != nil && strings.TrimSpace(log) == "" {
		t.Fatalf("go build: %v", err)
	}
	return log
}

func runGo(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBin, args...)
	cmd.Dir = dir
	cmd.Env = goEnv()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func goEnv() []string {
	drop := map[string]bool{
		"GOTOOLCHAIN": true,
		"GOROOT":      true,
		"GO111MODULE": true,
		"GOPROXY":     true,
		"CGO_ENABLED": true,
	}
	var env []string
	for _, e := range os.Environ() {
		key, _, ok := strings.Cut(e, "=")
		if ok && drop[key] {
			continue
		}
		env = append(env, e)
	}
	return append(env,
		"GOTOOLCHAIN=local",
		"GOROOT="+runtime.GOROOT(),
		"GO111MODULE=on",
		"GOPROXY=off",
		"CGO_ENABLED=1",
	)
}

func requireSysoPacked(t *testing.T, log, name string) {
	t.Helper()
	if !strings.Contains(log, name) {
		t.Fatalf("build did not pack %s:\n%s", name, log)
	}
}

func rejectFingerprintMismatch(t *testing.T, log string) {
	t.Helper()
	if strings.Contains(log, "fingerprint mismatch") {
		t.Fatalf("fingerprint mismatch aborted the link before directives could be applied:\n%s", tail(log))
	}
}

func workDir(log string) string {
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "WORK=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "WORK="))
		}
	}
	return ""
}

func findArchiveContaining(t *testing.T, root string, payload []byte) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return err
		}
		if !strings.HasSuffix(path, ".a") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Contains(body, payload) {
			found = path
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatalf("no archive under %s contains the .syso payload", root)
	}
	return found
}

func memberNameContaining(t *testing.T, archive, payload []byte) string {
	t.Helper()
	const armag = "!<arch>\n"
	if !bytes.HasPrefix(archive, []byte(armag)) {
		t.Fatalf("not an archive")
	}
	off := len(armag)
	for off < len(archive) {
		if off%2 != 0 {
			off++
		}
		if off+60 > len(archive) {
			break
		}
		hdr := archive[off : off+60]
		if string(hdr[58:60]) != "`\n" {
			t.Fatalf("bad archive header at %d", off)
		}
		name := strings.TrimSpace(string(hdr[:16]))
		size, err := strconv.Atoi(strings.TrimSpace(string(hdr[48:58])))
		if err != nil {
			t.Fatal(err)
		}
		start := off + 60
		if start+size > len(archive) {
			t.Fatalf("archive member %s overruns the file", name)
		}
		if bytes.Contains(archive[start:start+size], payload) {
			return name
		}
		off = start + size
	}
	t.Fatal("payload is not an archive member")
	return ""
}

func extractMember(t *testing.T, archive []byte, want string) []byte {
	t.Helper()
	const armag = "!<arch>\n"
	if !bytes.HasPrefix(archive, []byte(armag)) {
		t.Fatal("compile output is not an archive")
	}
	off := len(armag)
	for off < len(archive) {
		if off%2 != 0 {
			off++
		}
		if off+60 > len(archive) {
			break
		}
		hdr := archive[off : off+60]
		if string(hdr[58:60]) != "`\n" {
			t.Fatalf("bad archive header at %d", off)
		}
		name := strings.TrimSpace(string(hdr[:16]))
		size, err := strconv.Atoi(strings.TrimSpace(string(hdr[48:58])))
		if err != nil {
			t.Fatal(err)
		}
		start := off + 60
		if name == want {
			return append([]byte(nil), archive[start:start+size]...)
		}
		off = start + size
	}
	t.Fatalf("archive has no %s member", want)
	return nil
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func tail(s string) string {
	if len(s) <= 2000 {
		return s
	}
	return s[len(s)-2000:]
}
