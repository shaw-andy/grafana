package repository_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/dns/dnsmessage"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
)

// These tests are the spec for the git URL check-then-fetch bug.
//
// Admission resolves the repository hostname and rejects loopback, private,
// link-local, and unspecified answers. The git and GitHub clients built later
// dial that same hostname through net/http's default transport, which resolves
// it again and connects to whatever that resolution returns.
//
// TestRepositoryFetchDialsRebindingAfterAdmission changes DNS to a link-local
// address after admission, at the start of the dial. It fails while the fetch
// connects to that address.
//
// TestRepositoryFetchFollowsLookupAfterAddressCheck lets the lookup that a
// connection-time check would use return the public address, then returns the
// link-local address for every later lookup. It fails when a check and a later
// dial do not use the same addresses. A fix that only calls ValidateURL again
// and then dials the hostname still fails this test.
//
// Both tests pass when every connection goes to an address that was validated
// for that connection, or when the fetch refuses before connecting.
//
// Not covered, because these paths do not dial a repository URL:
//   - git History returns before any network call
//   - GitHub ResourceURLs and RefURLs only format strings
//   - githubEnterprise, bitbucket, and gitlab have no repository Build in this
//     tree, so admission can store their URLs but nothing fetches them
//   - GitHub connection clients are a different constructor and are not admitted
//     through RepositoryValidator
//
// GitHub CommentPullRequest, MergeBase, and branch-protection checks use the
// same API client as GetDefaultBranch and History. Those two calls exercise that
// client; the other methods do not open a second transport.

const rebindHost = "git.rebind.test"

func TestRepositoryFetchDialsRebindingAfterAdmission(t *testing.T) {
	env := newRebindEnv(t)

	gitObj := env.repository(provisioning.GitRepositoryType, "main")
	env.admit(t, gitObj)
	env.requireValidatorRejectsCurrentAnswer(t, gitObj, true)

	ghObj := env.repository(provisioning.GitHubRepositoryType, "main")
	env.admit(t, ghObj)

	for _, op := range gitFetchOps() {
		t.Run("git/"+op.name, func(t *testing.T) {
			env.armDialGate()
			repo := env.build(t, gitObj)
			op.call(t, repo)
			env.requireNoBlockedConnection(t)
		})
	}

	for _, op := range githubFetchOps() {
		t.Run("github/"+op.name, func(t *testing.T) {
			env.armDialGate()
			obj := ghObj
			if op.emptyBranch {
				obj = env.repository(provisioning.GitHubRepositoryType, "")
				env.admit(t, obj)
			}
			repo := env.build(t, obj)
			op.call(t, repo)
			env.requireNoBlockedConnection(t)
		})
	}
}

func TestRepositoryFetchFollowsLookupAfterAddressCheck(t *testing.T) {
	env := newRebindEnv(t)

	gitObj := env.repository(provisioning.GitRepositoryType, "main")
	env.admit(t, gitObj)
	env.armSecondLookup()
	gitRepo := env.build(t, gitObj)
	for _, op := range gitFetchOps() {
		op.call(t, gitRepo)
	}
	env.requireNoBlockedConnection(t)

	env.setMode(modePublic)
	ghObj := env.repository(provisioning.GitHubRepositoryType, "main")
	env.admit(t, ghObj)
	env.armSecondLookup()
	ghRepo := env.build(t, ghObj)
	for _, op := range githubFetchOps() {
		if op.emptyBranch {
			continue
		}
		op.call(t, ghRepo)
	}
	env.requireNoBlockedConnection(t)
}

type fetchOp struct {
	name        string
	emptyBranch bool
	call        func(t *testing.T, repo repository.Repository)
}

func gitFetchOps() []fetchOp {
	return []fetchOp{
		{name: "Test", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.Test(opCtx(t))
		}},
		{name: "GetDefaultBranch", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.BranchHandler).GetDefaultBranch(opCtx(t))
		}},
		{name: "ListRefs", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Versioned).ListRefs(opCtx(t))
		}},
		{name: "LatestRef", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Versioned).LatestRef(opCtx(t))
		}},
		{name: "Read", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Reader).Read(opCtx(t), "dashboard.json", "main")
		}},
		{name: "ReadTree", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Reader).ReadTree(opCtx(t), "main")
		}},
		{name: "CompareFiles", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Versioned).CompareFiles(opCtx(t), "main", "main")
		}},
		{name: "Create", call: func(t *testing.T, repo repository.Repository) {
			_ = repo.(repository.Writer).Create(opCtx(t), "dashboard.json", "main", []byte("x"), "create")
		}},
		{name: "Update", call: func(t *testing.T, repo repository.Repository) {
			_ = repo.(repository.Writer).Update(opCtx(t), "dashboard.json", "main", []byte("y"), "update")
		}},
		{name: "Write", call: func(t *testing.T, repo repository.Repository) {
			_ = repo.(repository.Writer).Write(opCtx(t), "dashboard.json", "main", []byte("z"), "write")
		}},
		{name: "Delete", call: func(t *testing.T, repo repository.Repository) {
			_ = repo.(repository.Writer).Delete(opCtx(t), "dashboard.json", "main", "delete")
		}},
		{name: "Move", call: func(t *testing.T, repo repository.Repository) {
			_ = repo.(repository.Writer).Move(opCtx(t), "dashboard.json", "moved.json", "main", "move")
		}},
		{name: "Stage", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.StageableRepository).Stage(opCtx(t), repository.StageOptions{Ref: "main"})
		}},
	}
}

func githubFetchOps() []fetchOp {
	return []fetchOp{
		{name: "GetDefaultBranch", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.BranchHandler).GetDefaultBranch(opCtx(t))
		}},
		{name: "History", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Versioned).History(opCtx(t), "dashboard.json", "main")
		}},
		{name: "Test", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.Test(opCtx(t))
		}},
		{name: "TestEmptyBranch", emptyBranch: true, call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.Test(opCtx(t))
		}},
		{name: "ListRefs", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Versioned).ListRefs(opCtx(t))
		}},
		{name: "Read", call: func(t *testing.T, repo repository.Repository) {
			_, _ = repo.(repository.Reader).Read(opCtx(t), "dashboard.json", "main")
		}},
		{name: "Create", call: func(t *testing.T, repo repository.Repository) {
			_ = repo.(repository.Writer).Create(opCtx(t), "dashboard.json", "main", []byte("x"), "create")
		}},
	}
}

func opCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

type rebindEnv struct {
	t            *testing.T
	factory      repository.Factory
	validator    *repository.URLValidator
	admission    *repository.AdmissionValidator
	url          string
	allowedIP    net.IP
	blockedIP    net.IP
	dnsAddr      string
	poisonOnDial atomicBool

	mu         sync.Mutex
	mode       resolveMode
	gavePublic bool
	queries    []string
	hits       []string
	blockedHit int
}

type resolveMode int

const (
	modePublic resolveMode = iota
	modeBlocked
	modeSecondLookup
)

func newRebindEnv(t *testing.T) *rebindEnv {
	t.Helper()

	allowedIP := net.ParseIP("192.0.2.1").To4()
	blockedIP := net.ParseIP("169.254.169.254").To4()
	require.NotNil(t, allowedIP)
	require.NotNil(t, blockedIP)
	require.False(t, isBlockedFixtureIP(allowedIP), "allowed fixture %s is classified as a blocked address", allowedIP)
	require.True(t, blockedIP.IsLinkLocalUnicast(), "blocked fixture %s is not link-local", blockedIP)

	ensureLoopbackAlias(t, allowedIP.String())
	ensureLoopbackAlias(t, blockedIP.String())

	allowedLn := listen(t, &net.TCPAddr{IP: allowedIP, Port: 0})
	port := allowedLn.Addr().(*net.TCPAddr).Port
	blockedLn := listen(t, &net.TCPAddr{IP: blockedIP, Port: port})

	env := &rebindEnv{
		t:         t,
		allowedIP: allowedIP,
		blockedIP: blockedIP,
		url:       fmt.Sprintf("http://%s:%d/owner/repo.git", rebindHost, port),
		mode:      modePublic,
	}
	env.serve(allowedLn, false)
	env.serve(blockedLn, true)
	env.serveDNS(t)
	env.installResolver(t)

	allowlist, err := repository.NewAllowlist(nil)
	require.NoError(t, err)
	env.validator = repository.NewURLValidator(allowlist, net.DefaultResolver.LookupIPAddr)

	decrypter := repository.ProvideDecrypter(nil, nil)
	factory, err := repository.ProvideFactory(
		map[provisioning.RepositoryType]struct{}{
			provisioning.GitRepositoryType:    {},
			provisioning.GitHubRepositoryType: {},
		},
		[]repository.Extra{
			git.Extra(decrypter, true, nil, nil),
			github.Extra(decrypter, github.ProvideFactory(), nil, true, nil, nil),
		},
		noop.NewTracerProvider().Tracer("rebind"),
	)
	require.NoError(t, err)
	env.factory = factory
	env.admission = repository.NewAdmissionValidator(nil, repository.NewValidator(false, factory, repository.WithURLValidator(env.validator)))
	return env
}

func (e *rebindEnv) repository(kind provisioning.RepositoryType, branch string) *provisioning.Repository {
	cfg := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "repo",
			Namespace:  "default",
			Finalizers: []string{repository.CleanFinalizer},
		},
		Spec: provisioning.RepositorySpec{
			Title: "Repo",
			Type:  kind,
		},
	}
	switch kind {
	case provisioning.GitRepositoryType:
		cfg.Spec.Git = &provisioning.GitRepositoryConfig{URL: e.url, Branch: branch, Path: "dashboards"}
	case provisioning.GitHubRepositoryType:
		cfg.Spec.GitHub = &provisioning.GitHubRepositoryConfig{URL: e.url, Branch: branch, Path: "dashboards"}
	default:
		e.t.Fatalf("unsupported repository type %s", kind)
	}
	return cfg
}

func (e *rebindEnv) admit(t *testing.T, obj *provisioning.Repository) {
	t.Helper()
	err := e.admission.Validate(context.Background(), admissionAttributes(obj), nil)
	require.NoError(t, err, "admission should accept %s while it resolves to %s", obj.URL(), e.allowedIP)
}

func (e *rebindEnv) requireValidatorRejectsCurrentAnswer(t *testing.T, obj *provisioning.Repository, restorePublic bool) {
	t.Helper()
	e.mu.Lock()
	previous := e.mode
	e.mode = modeBlocked
	e.mu.Unlock()

	err := e.validator.ValidateURL(context.Background(), obj.URL())
	require.Error(t, err, "validator should reject %s when DNS returns %s", obj.URL(), e.blockedIP)
	require.Contains(t, err.Error(), e.blockedIP.String())

	if restorePublic {
		e.mu.Lock()
		e.mode = previous
		e.mu.Unlock()
	}
}

func (e *rebindEnv) setMode(mode resolveMode) {
	e.mu.Lock()
	e.mode = mode
	e.mu.Unlock()
}

func (e *rebindEnv) armDialGate() {
	e.mu.Lock()
	e.mode = modePublic
	e.mu.Unlock()
	e.poisonOnDial.Store(true)
	e.resetHits()
}

func (e *rebindEnv) armSecondLookup() {
	e.mu.Lock()
	e.mode = modeSecondLookup
	e.gavePublic = false
	e.mu.Unlock()
	e.poisonOnDial.Store(false)
	e.resetHits()
}

func (e *rebindEnv) build(t *testing.T, obj *provisioning.Repository) repository.Repository {
	t.Helper()
	repo, err := e.factory.Build(context.Background(), obj)
	require.NoError(t, err)
	return repo
}

func (e *rebindEnv) resetHits() {
	e.mu.Lock()
	e.hits = nil
	e.blockedHit = 0
	e.queries = nil
	e.mu.Unlock()
}

func (e *rebindEnv) requireNoBlockedConnection(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.blockedHit == 0 {
		return
	}
	t.Errorf("fetch connected to %s after admission accepted %s (%s):\n%s\nqueries:\n%s",
		e.blockedIP, e.allowedIP, e.url, strings.Join(e.hits, "\n"), strings.Join(e.queries, "\n"))
}

func (e *rebindEnv) pickA(name string) (net.IP, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.EqualFold(strings.TrimSuffix(name, "."), rebindHost) {
		e.queries = append(e.queries, name+" NODATA")
		return nil, "NODATA"
	}
	var ip net.IP
	switch e.mode {
	case modeBlocked:
		ip = e.blockedIP
	case modeSecondLookup:
		if !e.gavePublic {
			e.gavePublic = true
			ip = e.allowedIP
		} else {
			ip = e.blockedIP
		}
	default:
		ip = e.allowedIP
	}
	e.queries = append(e.queries, fmt.Sprintf("%s A %s", name, ip))
	return ip, ip.String()
}

func (e *rebindEnv) serve(ln net.Listener, blocked bool) {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			e.mu.Lock()
			line := fmt.Sprintf("%s %s %s host=%s", r.Method, r.URL.RequestURI(), ln.Addr(), r.Host)
			e.hits = append(e.hits, line)
			if blocked {
				e.blockedHit++
			}
			e.mu.Unlock()
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusNotFound)
		}),
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	e.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
}

func (e *rebindEnv) serveDNS(t *testing.T) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	e.dnsAddr = conn.LocalAddr().String()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := e.dnsResponse(buf[:n])
			if resp == nil {
				continue
			}
			_, _ = conn.WriteTo(resp, addr)
		}
	}()
}

func (e *rebindEnv) dnsResponse(query []byte) []byte {
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil || len(msg.Questions) == 0 {
		return nil
	}
	q := msg.Questions[0]
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.Header.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   msg.Header.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{q},
	}
	if q.Type == dnsmessage.TypeA && q.Class == dnsmessage.ClassINET {
		if ip, _ := e.pickA(q.Name.String()); ip != nil {
			var a [4]byte
			copy(a[:], ip.To4())
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: a},
			}}
		}
	}
	packed, err := resp.Pack()
	if err != nil {
		return nil
	}
	return packed
}

func (e *rebindEnv) installResolver(t *testing.T) {
	t.Helper()
	previousResolver := net.DefaultResolver
	transport := http.DefaultTransport.(*http.Transport)
	previousDial := transport.DialContext
	previousKeepAlive := transport.DisableKeepAlives
	transport.DisableKeepAlives = true
	transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil && strings.EqualFold(host, rebindHost) && e.poisonOnDial.Load() {
			e.mu.Lock()
			e.mode = modeBlocked
			e.queries = append(e.queries, "dial "+addr)
			e.mu.Unlock()
		}
		return previousDial(ctx, network, addr)
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, e.dnsAddr)
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = previousResolver
		transport.DialContext = previousDial
		transport.DisableKeepAlives = previousKeepAlive
		transport.CloseIdleConnections()
	})
}

func listen(t *testing.T, addr net.Addr) net.Listener {
	t.Helper()
	var network, address string
	switch a := addr.(type) {
	case *net.TCPAddr:
		network = "tcp"
		address = a.String()
	default:
		network = "tcp"
		address = addr.String()
	}
	ln, err := net.Listen(network, address)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func ensureLoopbackAlias(t *testing.T, ip string) {
	t.Helper()
	out, err := exec.Command("sudo", "ip", "addr", "add", ip+"/32", "dev", "lo").CombinedOutput()
	if err != nil && !bytes.Contains(bytes.ToLower(out), []byte("file exists")) && !bytes.Contains(bytes.ToLower(out), []byte("already assigned")) {
		t.Fatalf("add loopback address %s: %v (%s)", ip, err, out)
	}
}

func isBlockedFixtureIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func admissionAttributes(obj *provisioning.Repository) admission.Attributes {
	return admission.NewAttributesRecord(
		obj,
		nil,
		provisioning.RepositoryResourceInfo.GroupVersionKind(),
		obj.Namespace,
		obj.Name,
		provisioning.RepositoryResourceInfo.GroupVersionResource(),
		"",
		admission.Create,
		nil,
		false,
		&user.DefaultInfo{},
	)
}

// atomicBool avoids importing sync/atomic under a name that hides the mutex.
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) Store(v bool) {
	b.mu.Lock()
	b.v = v
	b.mu.Unlock()
}

func (b *atomicBool) Load() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}
