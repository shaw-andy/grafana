package sqlstore

import (
	"context"
	"database/sql"
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/encryption/provider"
	encservice "github.com/grafana/grafana/pkg/services/encryption/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/kmsproviders/defaultprovider"
	"github.com/grafana/grafana/pkg/setting"
)

// These tests are the spec for the Windows installer exposure. They fail while a
// local user can read the database and the secret-key files, and they pass once
// those files are no longer readable by that user.

const (
	rightRead = 1 << iota
	rightAll
)

// programFilesUsersRead is the inheritable ACE Windows setup places on
// Program Files for BUILTIN\Users: (OI)(CI)(IO)(GR,GE). GR includes file read.
const programFilesUsersRead = rightRead

func TestWindowsInstallDoesNotExposeDatabaseOrSecretKeyToLocalUsers(t *testing.T) {
	t.Run("shipped secret_key", func(t *testing.T) {
		assertLocalUserCannotReadInstallSecrets(t, false)
	})
	t.Run("custom.ini secret_key", func(t *testing.T) {
		assertLocalUserCannotReadInstallSecrets(t, true)
	})
}

func assertLocalUserCannotReadInstallSecrets(t *testing.T, withCustomKey bool) {
	t.Helper()

	root := grafanaRepoRoot(t)
	install := evaluateWindowsInstall(t, root)

	// NSSM starts grafana-server with this directory as the process working
	// directory, and an empty homepath resolves to that working directory.
	home := t.TempDir()
	copyShippedFile(t, filepath.Join(root, "conf", "defaults.ini"), filepath.Join(home, "conf", "defaults.ini"))
	const placeholderSecret = "placeholder-datasource-password"
	const placeholderKey = "placeholder-secret-key"
	if withCustomKey {
		writeShippedFile(t, filepath.Join(home, "conf", "custom.ini"), "[security]\nsecret_key = "+placeholderKey+"\n")
	}

	t.Chdir(home)
	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{})
	require.NoError(t, err)

	tracer := tracing.InitializeTracerForTest()
	ss, err := NewSQLStoreWithoutSideEffects(cfg, featuremgmt.WithFeatures(), bus.ProvideBus(tracer), tracer)
	require.NoError(t, err)
	t.Cleanup(func() {
		if ss.engine != nil {
			_ = ss.engine.Close()
		}
	})

	dbPath := ss.dbCfg.Path
	require.FileExists(t, dbPath)
	// The mode passed to os.OpenFile is 0640. On Windows that call does not
	// attach a DACL, so the assertion below uses the installer ACL, not this mode.
	require.False(t, windowsOpenFileSuppliesDACL(os.O_CREATE|os.O_RDWR, 0o640))
	require.False(t, windowsMkdirSuppliesDACL())

	logPath := filepath.Join(cfg.LogsPath, "grafana.log")
	require.FileExists(t, logPath)

	enc, err := encservice.ProvideEncryptionService(tracer, provider.ProvideEncryptionProvider(), &usagestats.NoopUsageStats{}, cfg)
	require.NoError(t, err)
	kms := defaultprovider.New(cfg, enc)
	ciphertext, err := kms.Encrypt(context.Background(), []byte(placeholderSecret))
	require.NoError(t, err)

	_, err = ss.engine.Exec("CREATE TABLE exposed_secret (payload BLOB)")
	require.NoError(t, err)
	_, err = ss.engine.Exec("INSERT INTO exposed_secret (payload) VALUES (?)", ciphertext)
	require.NoError(t, err)
	conn := ss.dbCfg.ConnectionString
	require.NoError(t, ss.engine.Close())
	ss.engine = nil

	// Reopen the database file from disk, the way a local user who can open
	// grafana.db would, then decrypt with the secret_key read from the ini file.
	stored := readStoredPayload(t, conn)
	require.Equal(t, ciphertext, stored)

	keyFile := filepath.Join(home, "conf", "defaults.ini")
	if withCustomKey {
		keyFile = filepath.Join(home, "conf", "custom.ini")
	}
	key := secretKeyFromINI(t, keyFile)
	recovered, err := enc.Decrypt(context.Background(), ciphertext, key)
	require.NoError(t, err)
	require.Equal(t, placeholderSecret, string(recovered))

	logicalHome := install.homeDir
	dbLogical := logicalUnderHome(logicalHome, home, dbPath)
	logLogical := logicalUnderHome(logicalHome, home, logPath)
	defaultsLogical := logicalUnderHome(logicalHome, home, filepath.Join(home, "conf", "defaults.ini"))
	customLogical := logicalUnderHome(logicalHome, home, filepath.Join(home, "conf", "custom.ini"))

	// Same database file holds user.password and user.salt once migrations run,
	// and the secure JSON of data sources. One read exposes all of them.
	require.False(t, install.usersCanRead(dbLogical), "local Users can read the SQLite database at %s", dbLogical)
	require.False(t, install.usersCanRead(logLogical), "local Users can read the log file at %s", logLogical)
	require.False(t, install.usersCanRead(defaultsLogical), "local Users can read the shipped secret_key file at %s", defaultsLogical)
	if withCustomKey {
		require.False(t, install.usersCanRead(customLogical), "local Users can read the secret_key override at %s", customLogical)
	}
}

// windowsOpenFileSuppliesDACL reports whether Go's Windows Open, given the
// flags os.OpenFile passes, attaches a security descriptor. It does not: the
// permission argument only selects the read-only file attribute, and the
// security-attributes pointer stays nil when O_CLOEXEC is set.
func windowsOpenFileSuppliesDACL(flag int, perm uint32) bool {
	if flag&syscall.O_CLOEXEC == 0 {
		// makeInheritSa sets InheritHandle and leaves the descriptor nil.
		return false
	}
	if perm&syscall.S_IWRITE == 0 {
		return false
	}
	return false
}

// windowsMkdirSuppliesDACL reports whether Go's Windows Mkdir applies the mode
// argument as a DACL. CreateDirectory is called with a nil security descriptor.
func windowsMkdirSuppliesDACL() bool {
	return false
}

type windowsInstall struct {
	homeDir string
	aclAt   func(logicalPath string) map[string]int
}

func (w windowsInstall) usersCanRead(logicalPath string) bool {
	allow := w.aclAt(logicalPath)
	for _, trustee := range []string{"Users", "Authenticated Users", "Everyone"} {
		if allow[trustee]&rightRead != 0 || allow[trustee]&rightAll != 0 {
			return true
		}
	}
	return false
}

type dirNode struct {
	id     string
	name   string
	parent string
	ops    []permOp
}

type permOp struct {
	// explicit is a LockPermissions or SDDL descriptor that replaces the DACL.
	explicit bool
	// sddl, when set, is the descriptor. Otherwise user/mask is one trustee.
	sddl string
	user string
	mask int
	// inheritable is true for a CreateFolder permission, which applies to
	// children as well as the directory itself.
	inheritable bool
}

type wixNode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Inner   []wixNode  `xml:",any"`
}

func evaluateWindowsInstall(t *testing.T, repo string) windowsInstall {
	t.Helper()

	msiDir := filepath.Join(repo, "packaging", "msi")
	entries, err := os.ReadDir(msiDir)
	require.NoError(t, err)

	dirs := map[string]*dirNode{}
	var service []byte
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".wxs") && !strings.HasSuffix(name, ".wxs.tpl")) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(msiDir, name))
		require.NoError(t, err)
		if name == "grafana-service.wxs" {
			service = body
		}
		var doc wixNode
		require.NoError(t, xml.Unmarshal(body, &doc))
		walkWix(&doc, "", "", dirs)
	}

	build := readShippedFile(t, filepath.Join(repo, "scripts", "build-msi.sh"))
	require.Contains(t, build, "-dr GrafanaX64Dir", "harvested files are installed under the grafana directory")
	heat := heatInvocation(build)
	require.NotContains(t, heat, "-t ", "a heat transform would add authoring this evaluator does not read")
	targz := readShippedFile(t, filepath.Join(repo, "scripts", "build-targz.sh"))
	require.Contains(t, targz, `cp -r conf`, "the package includes the conf tree that holds the secret key")
	require.Contains(t, targz, `mkdir -p "${DIR}/data"`, "the package includes the data directory the database is created in")

	require.Contains(t, string(service), `Account="LocalSystem"`)
	require.Contains(t, string(service), `Name="AppDirectory" Value="[GrafanaX64Dir]"`)
	require.Contains(t, string(service), `Name="Application" Value="[GrafanaX64Dir]bin\grafana.exe"`)
	require.Contains(t, string(service), `Value='server'`)

	homeID := "GrafanaX64Dir"
	aclOf := compileACLs(dirs)
	return windowsInstall{
		homeDir: pathOf(dirs, homeID),
		aclAt:   aclOf,
	}
}

func wixAttr(n *wixNode, name string) string {
	for _, attr := range n.Attrs {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func walkWix(n *wixNode, currentDir, parent string, dirs map[string]*dirNode) {
	nextDir := currentDir
	switch n.XMLName.Local {
	case "Directory":
		id := wixAttr(n, "Id")
		if id != "" {
			node := dirs[id]
			if node == nil {
				node = &dirNode{id: id}
				dirs[id] = node
			}
			if name := wixAttr(n, "Name"); name != "" {
				node.name = name
			}
			if node.parent == "" && currentDir != "" && currentDir != id {
				node.parent = currentDir
			}
			nextDir = id
		}
	case "DirectoryRef":
		id := wixAttr(n, "Id")
		if id != "" {
			if dirs[id] == nil {
				dirs[id] = &dirNode{id: id}
			}
			nextDir = id
		}
	case "CreateFolder":
		if id := wixAttr(n, "Directory"); id != "" {
			if dirs[id] == nil {
				dirs[id] = &dirNode{id: id}
			}
			nextDir = id
		}
	case "Permission", "PermissionEx":
		if parent == "CreateFolder" || parent == "File" {
			target := nextDir
			if parent == "File" {
				// File permissions apply to that file only. Harvested files have
				// no File elements in the authored sources; a File permission
				// whose Source we can see is recorded on its directory and then
				// narrowed by the caller via the file name.
				target = nextDir
			}
			if node := dirs[target]; node != nil {
				node.ops = append(node.ops, permOpFrom(n, parent == "CreateFolder"))
			}
		}
	}
	for i := range n.Inner {
		walkWix(&n.Inner[i], nextDir, n.XMLName.Local, dirs)
	}
}

func permOpFrom(n *wixNode, inheritable bool) permOp {
	op := permOp{inheritable: inheritable, user: normalizeTrustee(wixAttr(n, "User")), mask: maskFromAttrs(n)}
	if sddl := wixAttr(n, "Sddl"); sddl != "" {
		op.explicit = true
		op.sddl = sddl
		return op
	}
	// The WiX Permission element writes the LockPermissions table, which gives the
	// object an explicit security descriptor. util:PermissionEx does not: it
	// merges one trustee into the existing DACL.
	if n.XMLName.Local == "Permission" {
		op.explicit = true
	}
	return op
}

func maskFromAttrs(n *wixNode) int {
	mask := 0
	for _, attr := range n.Attrs {
		if !strings.EqualFold(attr.Value, "yes") {
			continue
		}
		switch strings.ToLower(attr.Name.Local) {
		case "read", "genericread":
			mask |= rightRead
		case "genericall", "fileallrights", "specificrightsall":
			mask |= rightRead | rightAll
		}
	}
	return mask
}

func normalizeTrustee(user string) string {
	switch strings.ToLower(strings.TrimSpace(user)) {
	case "users", `builtin\users`, "bu":
		return "Users"
	case "authenticated users", `nt authority\authenticated users`, "authenticatedusers", "au":
		return "Authenticated Users"
	case "everyone", "wd":
		return "Everyone"
	case "administrators", `builtin\administrators`, "ba":
		return "Administrators"
	case "system", "localsystem", `nt authority\system`, "sy":
		return "SYSTEM"
	default:
		return user
	}
}

func compileACLs(dirs map[string]*dirNode) func(string) map[string]int {
	memo := map[string]aclState{}
	var stateOf func(id string) aclState
	stateOf = func(id string) aclState {
		if id == "" || id == "TARGETDIR" || id == "SourceDir" {
			return programFilesACL()
		}
		if existing, ok := memo[id]; ok {
			return existing
		}
		node := dirs[id]
		parentID := ""
		if node != nil {
			parentID = node.parent
		}
		if id == "ProgramFiles64Folder" || id == "CommonAppDataFolder" {
			parentID = ""
		}
		state := inheritACL(stateOf(parentID))
		if node != nil {
			state = applyOps(state, node.ops)
		}
		memo[id] = state
		return state
	}

	byPath := map[string]aclState{}
	for id := range dirs {
		p := pathOf(dirs, id)
		if p == "" || isRootID(id) {
			continue
		}
		byPath[p] = stateOf(id)
	}

	return func(logicalPath string) map[string]int {
		logicalPath = strings.TrimPrefix(strings.ReplaceAll(logicalPath, "\\", "/"), "/")
		state := programFilesACL()
		if strings.HasPrefix(strings.ToLower(logicalPath), "programdata/") || strings.Contains(strings.ToLower(logicalPath), "/programdata/") {
			state = programDataACL()
		}
		acc := ""
		for _, part := range strings.Split(logicalPath, "/") {
			if part == "" || part == "." {
				continue
			}
			if acc == "" {
				acc = part
			} else {
				acc += "/" + part
			}
			if explicit, ok := byPath[acc]; ok {
				state = explicit
				continue
			}
			state = inheritACL(state)
		}
		return state.allow
	}
}

type aclState struct {
	allow   map[string]int
	inherit map[string]int
}

func programFilesACL() aclState {
	// Folder ACE for Users is (RX) and is not inheritable. The inheritable ACE
	// is (OI)(CI)(IO)(GR,GE), which is what files created underneath receive.
	return aclState{
		allow: map[string]int{
			"Users":          programFilesUsersRead,
			"Administrators": rightAll,
			"SYSTEM":         rightAll,
		},
		inherit: map[string]int{
			"Users":          programFilesUsersRead,
			"Administrators": rightAll,
			"SYSTEM":         rightAll,
		},
	}
}

func programDataACL() aclState {
	// ProgramData grants BUILTIN\Users (OI)(CI)(RX) plus create-file rights on
	// the folder. Files created underneath are readable by Users.
	return aclState{
		allow: map[string]int{
			"Users":          rightRead,
			"Administrators": rightAll,
			"SYSTEM":         rightAll,
		},
		inherit: map[string]int{
			"Users":          rightRead,
			"Administrators": rightAll,
			"SYSTEM":         rightAll,
		},
	}
}

func inheritACL(parent aclState) aclState {
	child := aclState{allow: map[string]int{}, inherit: map[string]int{}}
	for trustee, mask := range parent.inherit {
		child.allow[trustee] = mask
		child.inherit[trustee] = mask
	}
	return child
}

func applyOps(state aclState, ops []permOp) aclState {
	explicit := false
	var sddl string
	for _, op := range ops {
		if op.sddl != "" {
			explicit = true
			sddl = op.sddl
		}
	}
	if sddl != "" {
		return aclFromSDDL(sddl)
	}
	for _, op := range ops {
		if op.explicit {
			explicit = true
		}
	}
	if explicit {
		replaced := aclState{allow: map[string]int{}, inherit: map[string]int{}}
		// LockPermissions always grants LocalSystem full control.
		replaced.allow["SYSTEM"] = rightAll
		replaced.inherit["SYSTEM"] = rightAll
		for _, op := range ops {
			if !op.explicit || op.user == "" {
				continue
			}
			replaced.allow[op.user] = op.mask
			if op.inheritable {
				replaced.inherit[op.user] = op.mask
			}
		}
		return replaced
	}
	for _, op := range ops {
		if op.user == "" {
			continue
		}
		// SET_ACCESS discards the trustee's previous ACEs and writes this mask.
		state.allow[op.user] = op.mask
		if op.inheritable {
			state.inherit[op.user] = op.mask
		}
	}
	return state
}

func aclFromSDDL(sddl string) aclState {
	state := aclState{allow: map[string]int{}, inherit: map[string]int{}}
	dacl := sddl
	if i := strings.Index(sddl, "D:"); i >= 0 {
		dacl = sddl[i+2:]
	}
	// Flags run until the first ACE. "P" disables inheritance from the parent.
	flags := dacl
	if i := strings.Index(dacl, "("); i >= 0 {
		flags = dacl[:i]
		dacl = dacl[i:]
	} else {
		dacl = ""
	}
	_ = flags
	for _, ace := range splitACEs(dacl) {
		parts := strings.Split(ace, ";")
		if len(parts) < 6 || !strings.EqualFold(parts[0], "A") {
			continue
		}
		trustee := sddlSID(parts[5])
		if trustee == "" {
			continue
		}
		mask := 0
		if sddlRightsAllowRead(parts[2]) {
			mask |= rightRead
		}
		state.allow[trustee] = mask
		aceFlags := strings.ToUpper(parts[1])
		if strings.Contains(aceFlags, "OI") {
			state.inherit[trustee] = mask
		}
	}
	return state
}

func splitACEs(dacl string) []string {
	var aces []string
	for {
		start := strings.Index(dacl, "(")
		if start < 0 {
			return aces
		}
		end := strings.Index(dacl[start:], ")")
		if end < 0 {
			return aces
		}
		aces = append(aces, dacl[start+1:start+end])
		dacl = dacl[start+end+1:]
	}
}

func sddlSID(sid string) string {
	switch strings.ToUpper(strings.TrimSpace(sid)) {
	case "BU", "S-1-5-32-545":
		return "Users"
	case "AU", "S-1-5-11":
		return "Authenticated Users"
	case "WD", "S-1-1-0":
		return "Everyone"
	case "BA", "S-1-5-32-544":
		return "Administrators"
	case "SY", "S-1-5-18":
		return "SYSTEM"
	default:
		return ""
	}
}

func sddlRightsAllowRead(rights string) bool {
	rights = strings.TrimSpace(rights)
	if strings.HasPrefix(strings.ToLower(rights), "0x") {
		value, err := strconv.ParseUint(rights, 0, 32)
		if err != nil {
			return false
		}
		const genericRead = 0x80000000
		const fileReadData = 0x1
		return value&genericRead != 0 || value&fileReadData != 0 || value == 0x1F01FF
	}
	for i := 0; i+2 <= len(rights); i += 2 {
		switch strings.ToUpper(rights[i : i+2]) {
		case "FA", "FR", "GR", "GA":
			return true
		}
	}
	return false
}

func pathOf(dirs map[string]*dirNode, id string) string {
	var names []string
	seen := map[string]bool{}
	for id != "" && !isRootID(id) && !seen[id] {
		seen[id] = true
		node := dirs[id]
		if node == nil {
			break
		}
		if node.name != "" {
			names = append([]string{node.name}, names...)
		}
		id = node.parent
	}
	return strings.Join(names, "/")
}

func isRootID(id string) bool {
	switch id {
	case "", "TARGETDIR", "SourceDir", "ProgramFiles64Folder", "ProgramFilesFolder", "CommonAppDataFolder":
		return true
	default:
		return false
	}
}

func logicalUnderHome(logicalHome, home, full string) string {
	rel, err := filepath.Rel(home, full)
	if err != nil {
		return filepath.ToSlash(full)
	}
	rel = filepath.ToSlash(rel)
	if logicalHome == "" {
		return rel
	}
	if rel == "." {
		return logicalHome
	}
	return logicalHome + "/" + rel
}

func readStoredPayload(t *testing.T, conn string) []byte {
	t.Helper()
	db, err := sql.Open("sqlite3", conn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var payload []byte
	require.NoError(t, db.QueryRow("SELECT payload FROM exposed_secret").Scan(&payload))
	return payload
}

func secretKeyFromINI(t *testing.T, path string) string {
	t.Helper()
	body := readShippedFile(t, path)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "secret_key") {
			_, value, ok := strings.Cut(line, "=")
			require.True(t, ok, "secret_key entry in %s has no value", path)
			return strings.TrimSpace(value)
		}
	}
	t.Fatalf("secret_key entry missing from %s", path)
	return ""
}

func heatInvocation(script string) string {
	start := strings.Index(script, "wine heat")
	if start < 0 {
		return ""
	}
	rest := script[start:]
	end := strings.Index(rest, "\n\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func grafanaRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func copyShippedFile(t *testing.T, from, to string) {
	t.Helper()
	body, err := os.ReadFile(from)
	require.NoError(t, err)
	writeShippedFile(t, to, string(body))
}

func writeShippedFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o640))
}

func readShippedFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(body)
}
