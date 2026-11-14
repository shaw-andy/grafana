package relyance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"
)

// placeholderAPIKey is an obvious stand-in for the Vault output named API_KEY.
// The test never uses a real credential.
const placeholderAPIKey = "placeholder-api-key"

const upstreamImage = "gcr.io/relyance-ext/compliance_inspector"

// imageRef matches the upstream image name plus an optional tag and an optional digest.
// distribution/reference ParseDockerRef (reference v0.6.0 normalize.go) keeps only the
// digest when both are present, so a literal @sha256: is a pin even if a tag is also written.
var imageRef = regexp.MustCompile(regexp.QuoteMeta(upstreamImage) + `(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-fA-F]{64})?`)

func TestRelyanceScanDoesNotGiveMovedReleaseTagTheAPIKey(t *testing.T) {
	h := harness(t)
	role := h.runWorkflowFile(t, "relyance-scan.yml")
	if role == "attacker" {
		t.Fatal("replaced release tag received API_KEY from the Relyance scan step")
	}
	if role != "trusted" && role != "absent" {
		t.Fatalf("scan step did not run a digest-pinned image, role %q", role)
	}
}

// A digest that is computed from the release tag at runtime is still the moved tag.
// The scan step must keep failing that shape: looking the name up again between
// pull and run selects whatever the tag points at now.
func TestDigestLookedUpFromReleaseTagStillGivesItTheAPIKey(t *testing.T) {
	h := harness(t)
	script := strings.Join([]string{
		"docker pull " + upstreamImage + ":release",
		"DIGEST=$(docker image inspect --format '{{index .RepoDigests 0}}' " + upstreamImage + ":release)",
		"docker pull \"$DIGEST\"",
		"docker run --rm -v ${{ github.workspace }}:/repo --env \"API_KEY=${{ env.API_KEY }}\" \"$DIGEST\"",
	}, "\n")
	role := h.runJob(t, scanEnv(), script)
	if role != "attacker" {
		t.Fatalf("runtime digest looked up from the release tag should still be the replaced image, role %q", role)
	}
}

// A literal digest in the run script does not follow a tag that moves afterwards.
func TestLiteralDigestPinDoesNotGiveMovedReleaseTagTheAPIKey(t *testing.T) {
	h := harness(t)
	literal := "sha256:" + strings.Repeat("ab", 32)
	script := strings.Join([]string{
		"docker pull " + upstreamImage + "@" + literal,
		"docker run --rm -v ${{ github.workspace }}:/repo --env \"API_KEY=${{ env.API_KEY }}\" " + upstreamImage + "@" + literal,
	}, " && ")
	role := h.runJob(t, scanEnv(), script)
	if role != "trusted" {
		t.Fatalf("literal digest pin should run the pinned image, role %q", role)
	}
}

// Control for the registry stand-in: after the release tag is moved, a pull by tag
// returns the new manifest and a pull by the previous digest returns the old one.
func TestMovedReleaseTagPullFollowsTheTagAndDigestDoesNot(t *testing.T) {
	h := harness(t)
	h.removeLocal(t)

	tagOut := h.docker(t, "pull", h.image+":release")
	if !strings.Contains(tagOut, h.attackerDigest) {
		t.Fatalf("pull by tag did not resolve the moved release tag to the replacement\n%s", tagOut)
	}
	digestOut := h.docker(t, "pull", h.image+"@"+h.trustedDigest)
	if !strings.Contains(digestOut, h.trustedDigest) {
		t.Fatalf("pull by digest followed the moved tag\n%s", digestOut)
	}
	tagID := h.docker(t, "image", "inspect", "--format", "{{.Id}}", h.image+":release")
	digestID := h.docker(t, "image", "inspect", "--format", "{{.Id}}", h.image+"@"+h.trustedDigest)
	if strings.TrimSpace(tagID) == strings.TrimSpace(digestID) {
		t.Fatal("tag pull and digest pull resolved to the same image after the tag moved")
	}
}

func scanEnv() map[string]string {
	return map[string]string{
		"API_KEY": "${{ fromJSON(steps.vault-secrets.outputs.secrets).API_KEY }}",
	}
}

type imageHarness struct {
	image          string
	trustedDigest  string
	attackerDigest string
	server         *http.Server
}

var (
	harnessOnce sync.Once
	harnessVal  *imageHarness
	harnessErr  error
)

func harness(t *testing.T) *imageHarness {
	t.Helper()
	harnessOnce.Do(func() {
		harnessVal, harnessErr = startHarness()
	})
	if harnessErr != nil {
		t.Fatalf("start image harness: %v", harnessErr)
	}
	return harnessVal
}

func startHarness() (*imageHarness, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker is required to run the scan step: %w", err)
	}
	reg := newTagRegistry()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: reg}
	go func() { _ = srv.Serve(ln) }()

	port := ln.Addr().(*net.TCPAddr).Port
	image := fmt.Sprintf("127.0.0.1:%d/compliance_inspector", port)
	h := &imageHarness{image: image, server: srv}

	root, err := os.MkdirTemp("", "relyance-images-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)

	if err := buildRoleImage(filepath.Join(root, "trusted"), image+":trusted", "trusted"); err != nil {
		return nil, err
	}
	if err := buildRoleImage(filepath.Join(root, "attacker"), image+":attacker", "attacker"); err != nil {
		return nil, err
	}
	if out, err := run("docker", "tag", image+":trusted", image+":release"); err != nil {
		return nil, fmt.Errorf("tag trusted release: %w\n%s", err, out)
	}
	if _, err := run("docker", "push", image+":release"); err != nil {
		return nil, fmt.Errorf("push trusted release: %w", err)
	}
	trustedRef, err := repoDigest(image + ":trusted")
	if err != nil {
		// The trusted tag was not pushed; the release push still records the digest.
		trustedRef, err = repoDigest(image + ":release")
		if err != nil {
			return nil, err
		}
	}
	h.trustedDigest = digestOf(trustedRef)

	if out, err := run("docker", "tag", image+":attacker", image+":release"); err != nil {
		return nil, fmt.Errorf("move release tag: %w\n%s", err, out)
	}
	if _, err := run("docker", "push", image+":release"); err != nil {
		return nil, fmt.Errorf("push moved release: %w", err)
	}
	attackerRef, err := repoDigest(image + ":attacker")
	if err != nil {
		return nil, err
	}
	h.attackerDigest = digestOf(attackerRef)
	if h.trustedDigest == "" || h.attackerDigest == "" || h.trustedDigest == h.attackerDigest {
		return nil, fmt.Errorf("digests trusted=%s attacker=%s", h.trustedDigest, h.attackerDigest)
	}
	return h, nil
}

func (h *imageHarness) runWorkflowFile(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	env, script, err := scanStep(body)
	if err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	if script == "" {
		return "absent"
	}
	return h.runJob(t, env, script)
}

func (h *imageHarness) runJob(t *testing.T, stepEnv map[string]string, script string) string {
	t.Helper()
	workspace := t.TempDir()
	// Vault output shape: get-vault-secrets sets output API_KEY, and the composite
	// action publishes toJSON of that step's outputs as the "secrets" output.
	secrets, err := json.Marshal(map[string]string{"API_KEY": placeholderAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]map[string]string{
		"vault-secrets": {"secrets": string(secrets)},
	}
	expandedEnv := map[string]string{}
	for key, value := range stepEnv {
		expanded, err := expandActions(value, workspace, expandedEnv, outputs)
		if err != nil {
			t.Fatalf("expand step env %s: %v", key, err)
		}
		expandedEnv[key] = expanded
	}
	// exportEnv on the vault action also publishes API_KEY to later steps.
	if _, ok := expandedEnv["API_KEY"]; !ok {
		expandedEnv["API_KEY"] = placeholderAPIKey
	}
	expanded, err := expandActions(script, workspace, expandedEnv, outputs)
	if err != nil {
		t.Fatalf("expand run script: %v", err)
	}
	rewritten := h.rewriteImageRefs(expanded)
	if !strings.Contains(rewritten, h.image) && !strings.Contains(rewritten, "docker run") {
		return "absent"
	}

	scriptPath := filepath.Join(workspace, "scan.sh")
	if err := os.WriteFile(scriptPath, []byte(rewritten), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-e", scriptPath)
	cmd.Dir = workspace
	cmd.Env = os.Environ()
	for key, value := range expandedEnv {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan script failed: %v\n%s\nrewritten script:\n%s", err, out, rewritten)
	}
	observed, err := os.ReadFile(filepath.Join(workspace, "observed-role"))
	if err != nil {
		t.Fatalf("scan container did not write a role: %v\n%s", err, out)
	}
	role, _, _ := strings.Cut(string(observed), "\n")
	return role
}

func (h *imageHarness) rewriteImageRefs(script string) string {
	return imageRef.ReplaceAllStringFunc(script, func(ref string) string {
		suffix := strings.TrimPrefix(ref, upstreamImage)
		if _, digest, ok := strings.Cut(suffix, "@"); ok && isDigest(digest) {
			// Literal digest. Retarget to the trusted image's digest: this registry
			// does not have the upstream manifest, and a digest does not follow the tag.
			return h.image + "@" + h.trustedDigest
		}
		if tag, ok := strings.CutPrefix(suffix, ":"); ok && tag != "" {
			return h.image + ":" + tag
		}
		return h.image
	})
}

func (h *imageHarness) removeLocal(t *testing.T) {
	t.Helper()
	_, _ = run("docker", "image", "rm", "-f", h.image+":release", h.image+":trusted", h.image+":attacker", h.image+"@"+h.trustedDigest, h.image+"@"+h.attackerDigest)
}

func (h *imageHarness) docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run("docker", args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func scanStep(body []byte) (map[string]string, string, error) {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Env map[string]string `yaml:"env"`
				Run string            `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &wf); err != nil {
		return nil, "", err
	}
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.Contains(step.Run, upstreamImage) {
				return step.Env, step.Run, nil
			}
		}
	}
	return nil, "", nil
}

// expandActions applies the runner's ${{ }} insertion. TemplateReader splits on
// "${{" and "}}", and a mixed literal/expression string is evaluated as format(),
// which concatenates the literal text with each expression's string value.
func expandActions(input, workspace string, env map[string]string, steps map[string]map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(input); {
		start := strings.Index(input[i:], "${{")
		if start < 0 {
			b.WriteString(input[i:])
			break
		}
		start += i
		b.WriteString(input[i:start])
		end, err := closeExpression(input, start+3)
		if err != nil {
			return "", err
		}
		value, err := evalExpr(strings.TrimSpace(input[start+3:end-1]), workspace, env, steps)
		if err != nil {
			return "", err
		}
		b.WriteString(value)
		i = end + 1
	}
	return b.String(), nil
}

func closeExpression(input string, from int) (int, error) {
	inString := false
	for i := from; i < len(input); i++ {
		if input[i] == '\'' {
			inString = !inString
			continue
		}
		if !inString && input[i] == '}' && i > from && input[i-1] == '}' {
			return i, nil
		}
	}
	return 0, fmt.Errorf("expression not closed")
}

func evalExpr(expr, workspace string, env map[string]string, steps map[string]map[string]string) (string, error) {
	expr = strings.TrimSpace(expr)
	name, rest, fn := splitCall(expr)
	if fn && strings.EqualFold(name, "fromJSON") {
		arg, after, err := splitArgs(rest)
		if err != nil {
			return "", err
		}
		raw, err := evalExpr(arg, workspace, env, steps)
		if err != nil {
			return "", err
		}
		var parsed any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return "", err
		}
		if after == "" {
			return raw, nil
		}
		if !strings.HasPrefix(after, ".") {
			return "", fmt.Errorf("unsupported expression %q", expr)
		}
		obj, ok := parsed.(map[string]any)
		if !ok {
			return "", fmt.Errorf("fromJSON result is not an object")
		}
		field := after[1:]
		value, ok := obj[field]
		if !ok {
			return "", fmt.Errorf("fromJSON result has no %s", field)
		}
		switch typed := value.(type) {
		case string:
			return typed, nil
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				return "", err
			}
			return string(encoded), nil
		}
	}
	parts := strings.Split(expr, ".")
	switch parts[0] {
	case "github":
		if len(parts) == 2 && parts[1] == "workspace" {
			return workspace, nil
		}
	case "env":
		if len(parts) == 2 {
			return env[parts[1]], nil
		}
	case "steps":
		if len(parts) == 4 && parts[2] == "outputs" {
			return steps[parts[1]][parts[3]], nil
		}
	}
	return "", fmt.Errorf("unsupported expression %q", expr)
}

func splitCall(expr string) (name, rest string, ok bool) {
	idx := strings.IndexByte(expr, '(')
	if idx <= 0 {
		return "", "", false
	}
	return expr[:idx], expr[idx:], true
}

func splitArgs(rest string) (arg, after string, err error) {
	if !strings.HasPrefix(rest, "(") {
		return "", "", fmt.Errorf("expected arguments")
	}
	depth := 0
	inString := false
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\'':
			inString = !inString
		case '(':
			if !inString {
				depth++
			}
		case ')':
			if !inString {
				depth--
				if depth == 0 {
					return strings.TrimSpace(rest[1:i]), rest[i+1:], nil
				}
			}
		}
	}
	return "", "", fmt.Errorf("arguments not closed")
}

func buildRoleImage(dir, tag, role string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	source := filepath.Join(dir, "main.go")
	body := fmt.Sprintf(`package main

import "os"

func main() {
	value := os.Getenv("API_KEY")
	_ = os.WriteFile("/repo/observed-role", []byte(%q+"\n"+value), 0o644)
}
`, role)
	if err := os.WriteFile(source, []byte(body), 0o644); err != nil {
		return err
	}
	mod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(mod, []byte("module role\n\ngo 1.26.6\n"), 0o644); err != nil {
		return err
	}
	bin := filepath.Join(dir, "inspector")
	cmd := exec.Command("go", "build", "-o", bin, source)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goArch())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %w\n%s", role, err, out)
	}
	dockerfile := "FROM scratch\nCOPY inspector /inspector\nENTRYPOINT [\"/inspector\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return err
	}
	if out, err := run("docker", "build", "-t", tag, dir); err != nil {
		return fmt.Errorf("docker build %s: %w\n%s", role, err, out)
	}
	return nil
}

func goArch() string {
	out, err := exec.Command("go", "env", "GOARCH").Output()
	if err != nil {
		return "amd64"
	}
	return strings.TrimSpace(string(out))
}

func repoDigest(ref string) (string, error) {
	out, err := run("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", ref)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w\n%s", ref, err, out)
	}
	var digests []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &digests); err != nil {
		return "", err
	}
	if len(digests) == 0 {
		return "", fmt.Errorf("no repo digest for %s", ref)
	}
	return digests[0], nil
}

func digestOf(ref string) string {
	_, digest, _ := strings.Cut(ref, "@")
	return digest
}

func isDigest(ref string) bool {
	algo, encoded, ok := strings.Cut(ref, ":")
	if !ok || algo != "sha256" || len(encoded) != 64 {
		return false
	}
	for _, c := range encoded {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// tagRegistry is the slice of distribution v3.1.2 that decides which manifest a
// pull receives. manifestDispatcher parses the URL reference: a digest is used
// as-is, anything else is a tag. GetManifest then calls tags.Get, and tagStore.Get
// reads the tag's current link. PutManifest overwrites that link when the ref is a tag.
type tagRegistry struct {
	mu        sync.Mutex
	seq       atomic.Uint64
	uploads   map[string][]byte
	blobs     map[string][]byte
	manifests map[string]storedManifest
	tags      map[string]string
}

type storedManifest struct {
	body      []byte
	mediaType string
}

func newTagRegistry() *tagRegistry {
	return &tagRegistry{
		uploads:   map[string][]byte{},
		blobs:     map[string][]byte{},
		manifests: map[string]storedManifest{},
		tags:      map[string]string{},
	}
}

func (reg *tagRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	kind, name, rest := splitRepoPath(parts)
	switch {
	case kind == "blobs" && r.Method == http.MethodPost && len(rest) == 1 && rest[0] == "uploads":
		id := fmt.Sprintf("%d", reg.seq.Add(1))
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id))
		w.Header().Set("Docker-Upload-UUID", id)
		w.Header().Set("Range", "0-0")
		w.WriteHeader(http.StatusAccepted)
	case kind == "blobs" && (r.Method == http.MethodPatch || r.Method == http.MethodPut) && len(rest) >= 2 && rest[0] == "uploads":
		body, _ := io.ReadAll(r.Body)
		id := rest[1]
		reg.mu.Lock()
		reg.uploads[id] = append(reg.uploads[id], body...)
		stored := append([]byte(nil), reg.uploads[id]...)
		if r.Method == http.MethodPut {
			dgst := r.URL.Query().Get("digest")
			if dgst == "" {
				sum := sha256.Sum256(stored)
				dgst = "sha256:" + hex.EncodeToString(sum[:])
			}
			reg.blobs[dgst] = stored
			delete(reg.uploads, id)
			reg.mu.Unlock()
			w.Header().Set("Docker-Content-Digest", dgst)
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, dgst))
			w.WriteHeader(http.StatusCreated)
			return
		}
		reg.mu.Unlock()
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id))
		w.Header().Set("Range", fmt.Sprintf("0-%d", len(stored)-1))
		w.Header().Set("Docker-Upload-UUID", id)
		w.WriteHeader(http.StatusAccepted)
	case kind == "blobs" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && len(rest) == 1:
		reg.mu.Lock()
		blob, ok := reg.blobs[rest[0]]
		reg.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Docker-Content-Digest", rest[0])
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(blob)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(blob)
	case kind == "manifests" && r.Method == http.MethodPut && len(rest) == 1:
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		dgst := "sha256:" + hex.EncodeToString(sum[:])
		ref := rest[0]
		reg.mu.Lock()
		reg.manifests[name+"@"+dgst] = storedManifest{body: body, mediaType: r.Header.Get("Content-Type")}
		if !isDigest(ref) {
			reg.tags[name+"|"+ref] = dgst
		}
		reg.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, dgst))
		w.WriteHeader(http.StatusCreated)
	case kind == "manifests" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && len(rest) == 1:
		ref := rest[0]
		reg.mu.Lock()
		dgst := ref
		if !isDigest(ref) {
			var ok bool
			dgst, ok = reg.tags[name+"|"+ref]
			if !ok {
				reg.mu.Unlock()
				http.NotFound(w, r)
				return
			}
		}
		manifest, ok := reg.manifests[name+"@"+dgst]
		reg.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Content-Type", manifest.mediaType)
		w.Header().Set("Content-Length", fmt.Sprint(len(manifest.body)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(manifest.body)
	default:
		http.NotFound(w, r)
	}
}

func splitRepoPath(parts []string) (kind, name string, rest []string) {
	if len(parts) < 4 || parts[0] != "v2" {
		return "", "", nil
	}
	for i, part := range parts {
		if part == "blobs" || part == "manifests" {
			return part, strings.Join(parts[1:i], "/"), parts[i+1:]
		}
	}
	return "", "", nil
}
