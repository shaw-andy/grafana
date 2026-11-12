package git_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
)

// These tests are the expected behavior for repository URL admission and for the
// git and GitHub clients that dial the admitted URL. They fail while a literal
// or later-resolved address in shared address space (100.64.0.0/10), multicast,
// or benchmarking space is still accepted and then contacted.

const (
	sharedRangeAddress   = "100.100.100.200"
	admissionBlockDetail = "repository URL host must resolve to a public or allowed address"
	responseMarker       = "shared-address-response-marker"
)

type admissionCase struct {
	name    string
	repo    provisioning.RepositoryType
	factory repository.Factory
	rawURL  string
}

func TestAdmissionRejectsNonPublicRanges(t *testing.T) {
	gitFactory := newGitFactory(t)
	permissive := allowAllFactory{}

	var cases []admissionCase
	blocked := []string{
		"100.64.0.1",
		sharedRangeAddress,
		"[::ffff:100.100.100.200]",
		"100.127.255.254",
		"224.0.0.1",
		"[ff02::1]",
		"198.18.0.1",
		"198.19.255.254",
	}
	kinds := []struct {
		name    string
		repo    provisioning.RepositoryType
		factory repository.Factory
	}{
		{"git", provisioning.GitRepositoryType, gitFactory},
		{"github", provisioning.GitHubRepositoryType, gitFactory},
		{"github enterprise", provisioning.GitHubEnterpriseRepositoryType, permissive},
		{"bitbucket", provisioning.BitbucketRepositoryType, permissive},
		{"gitlab", provisioning.GitLabRepositoryType, permissive},
	}
	for _, host := range blocked {
		rawURL := "http://" + host + "/owner/repo"
		for _, kind := range kinds {
			cases = append(cases, admissionCase{
				name:    kind.name + " " + host,
				repo:    kind.repo,
				factory: kind.factory,
				rawURL:  rawURL,
			})
		}
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := admit(t, newRepo(tt.repo, tt.rawURL), tt.factory, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), admissionBlockDetail)
		})
	}
}

func TestAdmissionAllowsPublicLiteralAndAllowlistedSharedAddress(t *testing.T) {
	fac := newGitFactory(t)

	t.Run("public literal", func(t *testing.T) {
		err := admit(t, newRepo(provisioning.GitRepositoryType, "https://93.184.216.34/owner/repo"), fac, nil)
		require.NoError(t, err)
	})

	t.Run("shared address on the allowlist", func(t *testing.T) {
		err := admit(t, newRepo(provisioning.GitRepositoryType, "http://"+sharedRangeAddress+"/owner/repo"), fac, []string{sharedRangeAddress})
		require.NoError(t, err)
	})
}

func TestAdmissionRejectsHostnameResolvingToSharedAddress(t *testing.T) {
	const host = "shared-git.invalid"
	holdHosts(t)
	setHostsEntry(t, host, sharedRangeAddress)
	waitForResolver(t, host, sharedRangeAddress)

	err := admit(t, newRepo(provisioning.GitRepositoryType, "http://"+host+"/owner/repo"), newGitFactory(t), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), admissionBlockDetail)
}

func TestGitBranchReadAndFileReadDoNotDialSharedAddress(t *testing.T) {
	addr, log := sharedListener(t)
	log.reset()
	rawURL := "http://" + addr + "/owner/repo"
	repo := newRepo(provisioning.GitRepositoryType, rawURL)
	fac := newGitFactory(t)

	err := admit(t, repo, fac, nil)
	if err == nil {
		built := buildRepository(t, fac, repo)
		require.Equal(t, rawURL, built.Config().URL())
		branchErr, readErr := readBranchAndFile(t, built)
		requests := log.snapshot()
		if len(requests) != 0 {
			t.Fatalf("git client dialed %s after admission allowed it\nrequests: %+v\nbranch error: %v\nread error: %v", addr, requests, branchErr, readErr)
		}
	}

	require.Error(t, err)
	require.Contains(t, err.Error(), admissionBlockDetail)
	require.Empty(t, log.snapshot())
}

func TestGitHubBranchReadAndFileReadDoNotDialSharedAddress(t *testing.T) {
	addr, log := sharedListener(t)
	log.reset()
	rawURL := "http://" + addr + "/owner/repo"
	repo := newRepo(provisioning.GitHubRepositoryType, rawURL)
	fac := newGitFactory(t)

	err := admit(t, repo, fac, nil)
	if err == nil {
		built := buildRepository(t, fac, repo)
		require.Equal(t, rawURL, built.Config().URL())
		branchErr, readErr := readBranchAndFile(t, built)
		requests := log.snapshot()
		if len(requests) != 0 {
			t.Fatalf("github client dialed %s after admission allowed it\nrequests: %+v\nbranch error: %v\nread error: %v", addr, requests, branchErr, readErr)
		}
	}

	require.Error(t, err)
	require.Contains(t, err.Error(), admissionBlockDetail)
	require.Empty(t, log.snapshot())
}

func TestGitDialDoesNotFollowSharedRebinding(t *testing.T) {
	assertRebindingDoesNotDial(t, provisioning.GitRepositoryType, "rebind-git.invalid")
}

func TestGitHubDialDoesNotFollowSharedRebinding(t *testing.T) {
	assertRebindingDoesNotDial(t, provisioning.GitHubRepositoryType, "rebind-github.invalid")
}

func assertRebindingDoesNotDial(t *testing.T, repoType provisioning.RepositoryType, host string) {
	t.Helper()
	addr, log := sharedListener(t)
	log.reset()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	rawURL := "http://" + net.JoinHostPort(host, port) + "/owner/repo"

	holdHosts(t)
	setHostsEntry(t, host, "93.184.216.34")
	waitForResolver(t, host, "93.184.216.34")

	repo := newRepo(repoType, rawURL)
	fac := newGitFactory(t)
	require.NoError(t, admit(t, repo, fac, nil))

	setHostsEntry(t, host, sharedRangeAddress)
	waitForResolver(t, host, sharedRangeAddress)

	built := buildRepository(t, fac, repo)
	require.Equal(t, rawURL, built.Config().URL())
	require.Empty(t, log.snapshot(), "building the repository dialed before the branch read")

	branchErr, readErr := readBranchAndFile(t, built)
	requests := log.snapshot()
	require.Emptyf(t, requests, "client dialed %s after the name resolved to a shared address\nrequests: %+v\nbranch error: %v\nread error: %v", addr, requests, branchErr, readErr)
	require.Error(t, branchErr)
	require.Error(t, readErr)
}

func admit(t *testing.T, repo *provisioning.Repository, fac repository.Factory, allow []string) error {
	t.Helper()
	allowlist, err := repository.NewAllowlist(allow)
	require.NoError(t, err)
	urlValidator := repository.NewURLValidator(allowlist, net.DefaultResolver.LookupIPAddr)
	validator := repository.NewValidator(false, fac, repository.WithURLValidator(urlValidator))
	admissionValidator := repository.NewAdmissionValidator(
		[]provisioning.SyncTargetType{provisioning.SyncTargetTypeFolder},
		validator,
	)
	return admissionValidator.Validate(context.Background(), admission.NewAttributesRecord(
		repo,
		nil,
		provisioning.RepositoryResourceInfo.GroupVersionKind(),
		"default",
		repo.Name,
		provisioning.RepositoryResourceInfo.GroupVersionResource(),
		"",
		admission.Create,
		nil,
		false,
		&user.DefaultInfo{Name: "org-admin"},
	), nil)
}

func buildRepository(t *testing.T, fac repository.Factory, repo *provisioning.Repository) repository.Repository {
	t.Helper()
	built, err := fac.Build(context.Background(), repo)
	require.NoError(t, err)
	return built
}

func readBranchAndFile(t *testing.T, repo repository.Repository) (error, error) {
	t.Helper()
	branchReader, ok := repo.(repository.BranchHandler)
	require.True(t, ok, "repository %T does not read branches", repo)
	fileReader, ok := repo.(repository.Reader)
	require.True(t, ok, "repository %T does not read files", repo)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	_, branchErr := branchReader.GetDefaultBranch(ctx)
	_, readErr := fileReader.Read(ctx, "dashboard.json", "main")
	return branchErr, readErr
}

func newGitFactory(t *testing.T) repository.Factory {
	t.Helper()
	decrypter := func(*provisioning.Repository) repository.SecureValues { return emptySecure{} }
	fac, err := repository.ProvideFactory(
		map[provisioning.RepositoryType]struct{}{
			provisioning.GitRepositoryType:    {},
			provisioning.GitHubRepositoryType: {},
		},
		[]repository.Extra{
			git.Extra(decrypter, false, nil, nil),
			github.Extra(decrypter, github.ProvideFactory(), nil, false, nil, nil),
		},
		noop.NewTracerProvider().Tracer("shared-address-test"),
	)
	require.NoError(t, err)
	return fac
}

func newRepo(repoType provisioning.RepositoryType, rawURL string) *provisioning.Repository {
	repo := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "repo",
			Finalizers: []string{repository.CleanFinalizer},
		},
		Spec: provisioning.RepositorySpec{
			Title: "Example",
			Type:  repoType,
		},
	}
	switch repoType {
	case provisioning.GitRepositoryType:
		repo.Spec.Git = &provisioning.GitRepositoryConfig{URL: rawURL}
	case provisioning.GitHubRepositoryType:
		repo.Spec.GitHub = &provisioning.GitHubRepositoryConfig{URL: rawURL}
	case provisioning.GitHubEnterpriseRepositoryType:
		repo.Spec.GitHubEnterprise = &provisioning.GitHubEnterpriseRepositoryConfig{URL: rawURL}
	case provisioning.BitbucketRepositoryType:
		repo.Spec.Bitbucket = &provisioning.BitbucketRepositoryConfig{URL: rawURL}
	case provisioning.GitLabRepositoryType:
		repo.Spec.GitLab = &provisioning.GitLabRepositoryConfig{URL: rawURL}
	default:
		panic("unsupported repository type " + repoType)
	}
	return repo
}

type emptySecure struct{}

func (emptySecure) Token(context.Context) (common.RawSecureValue, error) { return "", nil }
func (emptySecure) WebhookSecret(context.Context) (common.RawSecureValue, error) {
	return "", nil
}
func (emptySecure) CommitSigningKey(context.Context) (common.RawSecureValue, error) {
	return "", nil
}

// allowAllFactory stands in for repository types whose build implementations
// are not in this module. Admission still runs the shared URL check.
type allowAllFactory struct{}

func (allowAllFactory) Types() []provisioning.RepositoryType { return nil }
func (allowAllFactory) Build(context.Context, *provisioning.Repository) (repository.Repository, error) {
	return nil, fmt.Errorf("not used")
}
func (allowAllFactory) Mutate(context.Context, runtime.Object, runtime.Object) error { return nil }
func (allowAllFactory) Validate(context.Context, runtime.Object) field.ErrorList     { return nil }

var (
	listenerOnce sync.Once
	listenerAddr string
	listenerLog  *requestLog
	listenerErr  error
)

func sharedListener(t *testing.T) (string, *requestLog) {
	t.Helper()
	listenerOnce.Do(func() {
		listenerAddr, listenerLog, listenerErr = startSharedListener()
	})
	require.NoError(t, listenerErr)
	return listenerAddr, listenerLog
}

func startSharedListener() (string, *requestLog, error) {
	if err := ensureLoopbackAlias(sharedRangeAddress); err != nil {
		return "", nil, err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(sharedRangeAddress, "0"))
	if err != nil {
		return "", nil, fmt.Errorf("listen on %s: %w", sharedRangeAddress, err)
	}
	log := &requestLog{}
	server := &http.Server{Handler: log, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(ln) }()
	return ln.Addr().String(), log, nil
}

func ensureLoopbackAlias(ip string) error {
	probe, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err == nil {
		return probe.Close()
	}
	out, addErr := exec.Command("sudo", "-n", "ip", "addr", "add", ip+"/32", "dev", "lo").CombinedOutput()
	if addErr != nil && !strings.Contains(string(out), "File exists") {
		return fmt.Errorf("cannot bind %s locally and will not dial it on the network: %v %s", ip, addErr, out)
	}
	probe, err = net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return fmt.Errorf("bind %s after adding it to lo: %w", ip, err)
	}
	return probe.Close()
}

type requestLog struct {
	mu       sync.Mutex
	requests []recordedRequest
}

type recordedRequest struct {
	Method string
	Host   string
	URI    string
}

func (l *requestLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	l.mu.Lock()
	l.requests = append(l.requests, recordedRequest{Method: r.Method, Host: r.Host, URI: r.URL.RequestURI()})
	l.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, responseMarker)
}

func (l *requestLog) snapshot() []recordedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]recordedRequest, len(l.requests))
	copy(out, l.requests)
	return out
}

func (l *requestLog) reset() {
	l.mu.Lock()
	l.requests = nil
	l.mu.Unlock()
}

var hostsMu sync.Mutex

func holdHosts(t *testing.T) {
	t.Helper()
	hostsMu.Lock()
	t.Cleanup(func() { hostsMu.Unlock() })
}

func setHostsEntry(t *testing.T, host, ip string) {
	t.Helper()
	require.NoError(t, replaceHostsEntry(host, ip))
	t.Cleanup(func() { _ = replaceHostsEntry(host, "") })
}

func replaceHostsEntry(host, ip string) error {
	original, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, line := range strings.Split(string(original), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && containsField(fields[1:], host) {
			continue
		}
		if strings.TrimSpace(line) == "" && b.Len() == 0 {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if ip != "" {
		fmt.Fprintf(&b, "%s %s\n", ip, host)
	}
	tmp, err := os.CreateTemp("", "hosts-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	out, err := exec.Command("sudo", "-n", "cp", name, "/etc/hosts").CombinedOutput()
	if err != nil {
		return fmt.Errorf("update /etc/hosts: %v %s", err, out)
	}
	return nil
}

func containsField(fields []string, host string) bool {
	for _, field := range fields {
		if field == host {
			return true
		}
	}
	return false
}

// waitForResolver polls the process resolver until host resolves to want.
// The Go resolver keeps a parsed /etc/hosts for five seconds and ignores a
// newer mtime until that entry expires, so a rewrite is not visible immediately.
func waitForResolver(t *testing.T, host, want string) {
	t.Helper()
	wantIP := net.ParseIP(want)
	require.NotNil(t, wantIP)
	deadline := time.Now().Add(8 * time.Second)
	var last []net.IPAddr
	var lastErr error
	for {
		last, lastErr = net.DefaultResolver.LookupIPAddr(context.Background(), host)
		if lastErr == nil {
			for _, addr := range last {
				if addr.IP.Equal(wantIP) {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolver did not return %s for %s (last %v, err %v)", want, host, last, lastErr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
