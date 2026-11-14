package ci_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests model the GitHub Actions behavior that decides whether a
// pull request in this repository runs code from another repository with
// this repository's OIDC token and pull request token. They fail while a
// moving ref still receives those permissions.

const callerRepository = "grafana/grafana"

type permLevel int

const (
	permNone permLevel = iota
	permRead
	permWrite
)

func (l permLevel) String() string {
	switch l {
	case permRead:
		return "read"
	case permWrite:
		return "write"
	default:
		return "none"
	}
}

// permissionSet is nil when the workflow does not set permissions.
// An empty set is an explicit permissions: {} block.
type permissionSet map[string]permLevel

func (p permissionSet) get(key string) permLevel {
	if p == nil {
		return permNone
	}
	return p[key]
}

func (p permissionSet) clone() permissionSet {
	out := permissionSet{}
	for k, v := range p {
		out[k] = v
	}
	return out
}

// lessOrEqual is PermissionLevel.IsLessThanOrEqualTo from actions/runner
// v2.338.2 src/Sdk/WorkflowParser/Conversion/PermissionLevelExtensions.cs.
func lessOrEqual(level, max permLevel) bool {
	switch {
	case level == permNone:
		return true
	case level == permRead && (max == permRead || max == permWrite):
		return true
	case level == permWrite && max == permWrite:
		return true
	default:
		return false
	}
}

func violatesMax(requested, max permissionSet) bool {
	keys := map[string]struct{}{}
	for k := range requested {
		keys[k] = struct{}{}
	}
	for k := range max {
		keys[k] = struct{}{}
	}
	for k := range keys {
		if !lessOrEqual(requested.get(k), max.get(k)) {
			return true
		}
	}
	return false
}

// downgradeForkWrites applies the pull_request fork rule: write becomes read.
// pull_request_target is not downgraded. id-token has no read capability that
// mints a token; only write does.
func downgradeForkWrites(p permissionSet) permissionSet {
	out := p.clone()
	for k, v := range out {
		if v == permWrite {
			out[k] = permRead
		}
	}
	return out
}

type pullRequest struct {
	Event      string // pull_request or pull_request_target
	Action     string
	Base       string
	Files      []string
	Fork       bool
	Draft      bool
	Repository string
	HeadSHA    string
	Number     int
	Title      string
}

type usesRef struct {
	Raw    string
	Owner  string
	Repo   string
	Path   string
	Ref    string
	Local  bool
	Docker bool
}

func parseUses(raw string) (usesRef, error) {
	raw = strings.TrimSpace(raw)
	u := usesRef{Raw: raw}
	switch {
	case raw == "":
		return u, fmt.Errorf("empty uses")
	case strings.HasPrefix(raw, "docker://"):
		u.Docker = true
		return u, nil
	case strings.HasPrefix(raw, "./"), strings.HasPrefix(raw, "$/"):
		u.Local = true
		return u, nil
	}
	refSep := strings.LastIndex(raw, "@")
	if refSep <= 0 || refSep == len(raw)-1 {
		return u, fmt.Errorf("uses %q has no ref", raw)
	}
	u.Ref = raw[refSep+1:]
	body := raw[:refSep]
	slash := strings.IndexByte(body, '/')
	if slash <= 0 || slash == len(body)-1 {
		return u, fmt.Errorf("uses %q has no owner/repo", raw)
	}
	u.Owner = body[:slash]
	rest := body[slash+1:]
	next := strings.IndexByte(rest, '/')
	if next < 0 {
		u.Repo = rest
		return u, nil
	}
	u.Repo = rest[:next]
	u.Path = rest[next+1:]
	return u, nil
}

func (u usesRef) repository() string {
	if u.Owner == "" || u.Repo == "" {
		return ""
	}
	return u.Owner + "/" + u.Repo
}

var fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// movingRef is true when a later push can change the bytes that run.
// A full commit SHA cannot. Branch names and tags can.
func movingRef(ref string) bool {
	return !fullSHA.MatchString(ref)
}

type job struct {
	ID          string
	If          string
	Permissions *permissionSet
	Uses        string
	With        map[string]string
	Steps       []step
}

type step struct {
	Name string
	Uses string
	With map[string]string
}

type workflow struct {
	Name        string
	File        string
	Events      map[string]*eventFilter
	Permissions *permissionSet
	Jobs        []job
}

type eventFilter struct {
	Types        []string
	Branches     []string
	Paths        []string
	PathsIgnore  []string
	BranchIgnore []string
}

type credentialUse struct {
	WorkflowFile string
	JobID        string
	Uses         string
	Permissions  permissionSet
	OIDCRepo     string
	OIDCRef      string
	StatusRepo   string
	StatusSHA    string
	LabeledRepo  string
	PullNumber   int
	Inputs       map[string]string
}

func (c credentialUse) privileged() bool {
	return c.Permissions.get("id-token") == permWrite ||
		c.Permissions.get("pull-requests") == permWrite ||
		c.Permissions.get("statuses") == permWrite
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func loadWorkflow(t *testing.T, path string) workflow {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	wf, err := parseWorkflow(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	wf.File = path
	return wf
}

func parseWorkflow(data []byte) (workflow, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return workflow{}, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return workflow{}, fmt.Errorf("workflow is not a YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return workflow{}, fmt.Errorf("workflow root is not a mapping")
	}
	wf := workflow{Events: map[string]*eventFilter{}}
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i].Value
		val := root.Content[i+1]
		switch key {
		case "name":
			wf.Name = val.Value
		case "on":
			events, err := parseEvents(val)
			if err != nil {
				return workflow{}, err
			}
			wf.Events = events
		case "permissions":
			perms, err := parsePermissions(val)
			if err != nil {
				return workflow{}, err
			}
			wf.Permissions = &perms
		case "jobs":
			jobs, err := parseJobs(val)
			if err != nil {
				return workflow{}, err
			}
			wf.Jobs = jobs
		}
	}
	return wf, nil
}

func parseEvents(node *yaml.Node) (map[string]*eventFilter, error) {
	events := map[string]*eventFilter{}
	switch node.Kind {
	case yaml.ScalarNode:
		events[node.Value] = &eventFilter{}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("event list contains a non-scalar")
			}
			events[item.Value] = &eventFilter{}
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			name := node.Content[i].Value
			body := node.Content[i+1]
			filter := &eventFilter{}
			if body.Kind == yaml.MappingNode {
				for j := 0; j < len(body.Content); j += 2 {
					switch body.Content[j].Value {
					case "types":
						filter.Types = scalarList(body.Content[j+1])
					case "branches":
						filter.Branches = scalarList(body.Content[j+1])
					case "branches-ignore":
						filter.BranchIgnore = scalarList(body.Content[j+1])
					case "paths":
						filter.Paths = scalarList(body.Content[j+1])
					case "paths-ignore":
						filter.PathsIgnore = scalarList(body.Content[j+1])
					}
				}
			}
			events[name] = filter
		}
	default:
		return nil, fmt.Errorf("unsupported on: kind %d", node.Kind)
	}
	return events, nil
}

func scalarList(node *yaml.Node) []string {
	if node.Kind == yaml.ScalarNode {
		return []string{node.Value}
	}
	var out []string
	for _, item := range node.Content {
		out = append(out, item.Value)
	}
	return out
}

func parsePermissions(node *yaml.Node) (permissionSet, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Value {
		case "read-all":
			return readAllPermissions(), nil
		case "write-all":
			return writeAllPermissions(), nil
		case "{}":
			return permissionSet{}, nil
		default:
			return nil, fmt.Errorf("unsupported permissions scalar %q", node.Value)
		}
	case yaml.MappingNode:
		// Specifying any key sets every omitted key to none.
		perms := permissionSet{}
		for i := 0; i < len(node.Content); i += 2 {
			level, err := parseLevel(node.Content[i+1].Value)
			if err != nil {
				return nil, err
			}
			perms[node.Content[i].Value] = level
		}
		return perms, nil
	default:
		return nil, fmt.Errorf("unsupported permissions kind %d", node.Kind)
	}
}

func parseLevel(value string) (permLevel, error) {
	switch value {
	case "none":
		return permNone, nil
	case "read":
		return permRead, nil
	case "write":
		return permWrite, nil
	default:
		return permNone, fmt.Errorf("unsupported permission level %q", value)
	}
}

func readAllPermissions() permissionSet {
	keys := []string{
		"actions", "checks", "contents", "deployments", "discussions", "id-token",
		"issues", "packages", "pages", "pull-requests", "security-events", "statuses",
	}
	perms := permissionSet{}
	for _, key := range keys {
		if key == "id-token" {
			// id-token has no read level. read-all does not mint a token.
			perms[key] = permNone
			continue
		}
		perms[key] = permRead
	}
	return perms
}

func writeAllPermissions() permissionSet {
	perms := readAllPermissions()
	for key := range perms {
		perms[key] = permWrite
	}
	perms["id-token"] = permWrite
	return perms
}

func parseJobs(node *yaml.Node) ([]job, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("jobs is not a mapping")
	}
	var jobs []job
	for i := 0; i < len(node.Content); i += 2 {
		id := node.Content[i].Value
		body := node.Content[i+1]
		if body.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("job %s is not a mapping", id)
		}
		parsed := job{ID: id}
		for j := 0; j < len(body.Content); j += 2 {
			key := body.Content[j].Value
			val := body.Content[j+1]
			switch key {
			case "if":
				parsed.If = val.Value
			case "uses":
				parsed.Uses = val.Value
			case "permissions":
				perms, err := parsePermissions(val)
				if err != nil {
					return nil, fmt.Errorf("job %s permissions: %w", id, err)
				}
				parsed.Permissions = &perms
			case "with":
				parsed.With = scalarMap(val)
			case "steps":
				steps, err := parseSteps(val)
				if err != nil {
					return nil, fmt.Errorf("job %s steps: %w", id, err)
				}
				parsed.Steps = steps
			}
		}
		jobs = append(jobs, parsed)
	}
	return jobs, nil
}

func parseSteps(node *yaml.Node) ([]step, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("steps is not a sequence")
	}
	var steps []step
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		var parsed step
		for i := 0; i < len(item.Content); i += 2 {
			switch item.Content[i].Value {
			case "name":
				parsed.Name = item.Content[i+1].Value
			case "uses":
				parsed.Uses = item.Content[i+1].Value
			case "with":
				parsed.With = scalarMap(item.Content[i+1])
			}
		}
		steps = append(steps, parsed)
	}
	return steps, nil
}

func scalarMap(node *yaml.Node) map[string]string {
	out := map[string]string{}
	if node.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i < len(node.Content); i += 2 {
		out[node.Content[i].Value] = node.Content[i+1].Value
	}
	return out
}

func jobPermissions(wf workflow, jb job) (permissionSet, bool) {
	// Job permissions replace workflow permissions. A job without a block
	// inherits an explicit workflow block. No block at either level keeps
	// the organization default, which is not in this repository.
	if jb.Permissions != nil {
		return jb.Permissions.clone(), true
	}
	if wf.Permissions != nil {
		return wf.Permissions.clone(), true
	}
	return nil, false
}

func eventMatches(filter *eventFilter, pr pullRequest) bool {
	if filter == nil {
		return false
	}
	if len(filter.Types) > 0 && !contains(filter.Types, pr.Action) {
		return false
	}
	if !branchAllowed(filter, pr.Base) {
		return false
	}
	if len(filter.Paths) == 0 && len(filter.PathsIgnore) == 0 {
		return true
	}
	if len(pr.Files) == 0 {
		return false
	}
	matched := false
	for _, file := range pr.Files {
		if pathSelected(filter, file) {
			matched = true
			break
		}
	}
	return matched
}

func branchAllowed(filter *eventFilter, base string) bool {
	if len(filter.Branches) == 0 && len(filter.BranchIgnore) == 0 {
		return true
	}
	if len(filter.BranchIgnore) > 0 {
		for _, pattern := range filter.BranchIgnore {
			if matchFilter(pattern, base) {
				return false
			}
		}
		return true
	}
	return matchFilterList(filter.Branches, base)
}

func pathSelected(filter *eventFilter, file string) bool {
	if len(filter.PathsIgnore) > 0 {
		for _, pattern := range filter.PathsIgnore {
			if matchFilter(pattern, file) {
				return false
			}
		}
		return true
	}
	return matchFilterList(filter.Paths, file)
}

func matchFilterList(patterns []string, value string) bool {
	matched := false
	for _, pattern := range patterns {
		neg := strings.HasPrefix(pattern, "!")
		body := pattern
		if neg {
			body = strings.TrimPrefix(pattern, "!")
		}
		if matchFilter(body, value) {
			matched = !neg
		}
	}
	return matched
}

func matchFilter(pattern, value string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("?")
		case '.', '+', '(', ')', '|', '^', '$', '\\', '[', ']', '{', '}':
			b.WriteByte('\\')
			b.WriteByte(pattern[i])
		default:
			b.WriteByte(pattern[i])
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

type exprValue struct {
	kind string // bool, string
	b    bool
	s    string
}

func evalIf(expression string, pr pullRequest) (bool, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return true, nil
	}
	expression = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expression, "${{"), "}}"))
	parser := &exprParser{s: expression, pr: pr}
	value, err := parser.parseOr()
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(parser.s) != "" {
		return false, fmt.Errorf("trailing expression %q", parser.s)
	}
	if value.kind != "bool" {
		return false, fmt.Errorf("if did not evaluate to a bool")
	}
	return value.b, nil
}

type exprParser struct {
	s  string
	pr pullRequest
}

func (p *exprParser) parseOr() (exprValue, error) {
	left, err := p.parseAnd()
	if err != nil {
		return exprValue{}, err
	}
	for {
		p.skip()
		if !strings.HasPrefix(p.s, "||") {
			return left, nil
		}
		p.s = p.s[2:]
		right, err := p.parseAnd()
		if err != nil {
			return exprValue{}, err
		}
		if left.kind != "bool" || right.kind != "bool" {
			return exprValue{}, fmt.Errorf("|| on non-bools")
		}
		left = exprValue{kind: "bool", b: left.b || right.b}
	}
}

func (p *exprParser) parseAnd() (exprValue, error) {
	left, err := p.parseEquality()
	if err != nil {
		return exprValue{}, err
	}
	for {
		p.skip()
		if !strings.HasPrefix(p.s, "&&") {
			return left, nil
		}
		p.s = p.s[2:]
		right, err := p.parseEquality()
		if err != nil {
			return exprValue{}, err
		}
		if left.kind != "bool" || right.kind != "bool" {
			return exprValue{}, fmt.Errorf("&& on non-bools")
		}
		left = exprValue{kind: "bool", b: left.b && right.b}
	}
}

func (p *exprParser) parseEquality() (exprValue, error) {
	left, err := p.parseUnary()
	if err != nil {
		return exprValue{}, err
	}
	p.skip()
	op := ""
	switch {
	case strings.HasPrefix(p.s, "=="):
		op = "=="
	case strings.HasPrefix(p.s, "!="):
		op = "!="
	default:
		return left, nil
	}
	p.s = p.s[2:]
	right, err := p.parseUnary()
	if err != nil {
		return exprValue{}, err
	}
	equal := left.kind == right.kind && ((left.kind == "bool" && left.b == right.b) || (left.kind == "string" && left.s == right.s))
	if op == "!=" {
		equal = !equal
	}
	return exprValue{kind: "bool", b: equal}, nil
}

func (p *exprParser) parseUnary() (exprValue, error) {
	p.skip()
	if strings.HasPrefix(p.s, "!") && !strings.HasPrefix(p.s, "!=") {
		p.s = p.s[1:]
		value, err := p.parseUnary()
		if err != nil {
			return exprValue{}, err
		}
		if value.kind != "bool" {
			return exprValue{}, fmt.Errorf("! on non-bool")
		}
		return exprValue{kind: "bool", b: !value.b}, nil
	}
	return p.parsePrimary()
}

func (p *exprParser) parsePrimary() (exprValue, error) {
	p.skip()
	if p.s == "" {
		return exprValue{}, fmt.Errorf("unexpected end of expression")
	}
	if p.s[0] == '(' {
		p.s = p.s[1:]
		value, err := p.parseOr()
		if err != nil {
			return exprValue{}, err
		}
		p.skip()
		if !strings.HasPrefix(p.s, ")") {
			return exprValue{}, fmt.Errorf("missing )")
		}
		p.s = p.s[1:]
		return value, nil
	}
	if p.s[0] == '\'' || p.s[0] == '"' {
		quote := p.s[0]
		p.s = p.s[1:]
		end := strings.IndexByte(p.s, quote)
		if end < 0 {
			return exprValue{}, fmt.Errorf("unterminated string")
		}
		value := p.s[:end]
		p.s = p.s[end+1:]
		return exprValue{kind: "string", s: value}, nil
	}
	i := 0
	for i < len(p.s) && (isIdent(p.s[i]) || p.s[i] == '.') {
		i++
	}
	if i == 0 {
		return exprValue{}, fmt.Errorf("cannot parse %q", p.s)
	}
	word := p.s[:i]
	p.s = p.s[i:]
	switch word {
	case "true":
		return exprValue{kind: "bool", b: true}, nil
	case "false":
		return exprValue{kind: "bool", b: false}, nil
	}
	return lookupContext(word, p.pr)
}

func (p *exprParser) skip() {
	p.s = strings.TrimLeft(p.s, " \t\r\n")
}

func isIdent(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func lookupContext(path string, pr pullRequest) (exprValue, error) {
	switch path {
	case "github.event_name":
		return exprValue{kind: "string", s: pr.Event}, nil
	case "github.repository":
		return exprValue{kind: "string", s: pr.Repository}, nil
	case "github.event.action":
		return exprValue{kind: "string", s: pr.Action}, nil
	case "github.event.pull_request.head.repo.fork":
		return exprValue{kind: "bool", b: pr.Fork}, nil
	case "github.event.pull_request.draft":
		return exprValue{kind: "bool", b: pr.Draft}, nil
	case "github.event.pull_request.base.ref":
		return exprValue{kind: "string", s: pr.Base}, nil
	case "github.event.pull_request.head.sha":
		return exprValue{kind: "string", s: pr.HeadSHA}, nil
	case "github.event.pull_request.title":
		return exprValue{kind: "string", s: pr.Title}, nil
	case "github.event.number":
		return exprValue{kind: "string", s: strconv.Itoa(pr.Number)}, nil
	case "github.head_ref":
		return exprValue{kind: "string", s: "topic"}, nil
	default:
		return exprValue{}, fmt.Errorf("unsupported context %s", path)
	}
}

// externalCodeRuns reports uses that execute bytes from a repository other
// than the caller when the ref is not a full commit SHA.
func externalCodeRuns(raw, callerRepo string) (usesRef, bool) {
	uses, err := parseUses(raw)
	if err != nil || uses.Local || uses.Docker || uses.repository() == "" {
		return uses, false
	}
	if uses.repository() == callerRepo {
		return uses, false
	}
	// actions/* and github/* are published by the platform that already
	// issues the token. A push there is not a separate trust boundary.
	if uses.Owner == "actions" || uses.Owner == "github" {
		return uses, false
	}
	if !movingRef(uses.Ref) {
		return uses, false
	}
	return uses, true
}

func sharesWritersToolkitBug(uses usesRef) bool {
	if uses.repository() == "grafana/writers-toolkit" {
		return true
	}
	// Other repositories are in this check only when the caller invokes a
	// reusable workflow. Action refs in those repositories are a separate
	// trust boundary and are named as untested.
	reusable := strings.HasPrefix(uses.Path, ".github/workflows/") &&
		(strings.HasSuffix(uses.Path, ".yml") || strings.HasSuffix(uses.Path, ".yaml"))
	return reusable
}

func evaluate(wf workflow, pr pullRequest) ([]credentialUse, error) {
	filter := wf.Events[pr.Event]
	if !eventMatches(filter, pr) {
		return nil, nil
	}
	var uses []credentialUse
	for _, jb := range wf.Jobs {
		candidates := movingCandidates(jb, pr.Repository)
		if len(candidates) == 0 {
			continue
		}
		run, err := evalIf(jb.If, pr)
		if err != nil {
			return nil, fmt.Errorf("%s job %s if: %w", wf.File, jb.ID, err)
		}
		if !run {
			continue
		}
		perms, explicit := jobPermissions(wf, jb)
		if !explicit {
			return nil, fmt.Errorf("%s job %s calls %s without a permissions block in the workflow", wf.File, jb.ID, candidates[0].Raw)
		}
		if pr.Event == "pull_request" && pr.Fork {
			perms = downgradeForkWrites(perms)
		}
		for _, parsed := range candidates {
			uses = append(uses, authorize(wf, jb, parsed, perms, pr))
		}
	}
	return uses, nil
}

func movingCandidates(jb job, callerRepo string) []usesRef {
	var raw []string
	if jb.Uses != "" {
		raw = append(raw, jb.Uses)
	}
	for _, st := range jb.Steps {
		if st.Uses != "" {
			raw = append(raw, st.Uses)
		}
	}
	var out []usesRef
	for _, item := range raw {
		parsed, runExternal := externalCodeRuns(item, callerRepo)
		if runExternal && sharesWritersToolkitBug(parsed) {
			out = append(out, parsed)
		}
	}
	return out
}

func authorize(wf workflow, jb job, uses usesRef, perms permissionSet, pr pullRequest) credentialUse {
	// The called code may request up to the caller job's permissions.
	// Requesting more makes the workflow invalid, so the bytes that run
	// are the ones that stay inside this set. Fork downgrade already
	// happened. id-token write is what lets a step request the JWT, and
	// the JWT repository claim is the caller. statuses write and
	// pull-requests write authorize the caller repository only.
	out := credentialUse{
		WorkflowFile: wf.File,
		JobID:        jb.ID,
		Uses:         uses.Raw,
		Permissions:  perms.clone(),
		Inputs:       jb.With,
	}
	if perms.get("id-token") == permWrite {
		out.OIDCRepo = pr.Repository
		ref := uses.Ref
		if !strings.HasPrefix(ref, "refs/") {
			// Branch-like refs are exposed as refs/heads/<ref> when the
			// ref is a branch. Tags stay as the tag name in the use, and
			// the claim uses refs/tags. The caller here uses a branch.
			if strings.Contains(uses.Path, ".github/workflows/") {
				ref = "refs/heads/" + uses.Ref
			}
		}
		out.OIDCRef = uses.repository() + "/" + uses.Path + "@" + ref
		if uses.Path == "" {
			out.OIDCRef = uses.repository() + "@" + uses.Ref
		}
	}
	if perms.get("statuses") == permWrite {
		out.StatusRepo = pr.Repository
		out.StatusSHA = pr.HeadSHA
	}
	if perms.get("pull-requests") == permWrite {
		out.LabeledRepo = pr.Repository
		out.PullNumber = pr.Number
	}
	return out
}

func docsPullRequest(action string, fork bool, files ...string) pullRequest {
	if len(files) == 0 {
		files = []string{"docs/sources/example.md"}
	}
	return pullRequest{
		Event:      "pull_request",
		Action:     action,
		Base:       "main",
		Files:      files,
		Fork:       fork,
		Repository: callerRepository,
		HeadSHA:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Number:     418,
		Title:      "Document the preview",
	}
}

func actedOnOtherRepo(use credentialUse, repo string) bool {
	if repo == callerRepository {
		return false
	}
	return use.StatusRepo == repo || use.LabeledRepo == repo || use.OIDCRepo == repo
}

func assertNoPrivilegedUse(t *testing.T, uses []credentialUse) {
	t.Helper()
	for _, use := range uses {
		if !use.privileged() {
			continue
		}
		t.Errorf("%s job %s runs %s with id-token=%s pull-requests=%s statuses=%s; OIDC repository %q ref %q; status repository %q; pull request repository %q; inputs %v",
			use.WorkflowFile, use.JobID, use.Uses,
			use.Permissions.get("id-token"), use.Permissions.get("pull-requests"), use.Permissions.get("statuses"),
			use.OIDCRepo, use.OIDCRef, use.StatusRepo, use.LabeledRepo, use.Inputs)
	}
}

func TestDeployPreviewMovingRefDoesNotReceiveCallerCredentials(t *testing.T) {
	wf := loadWorkflow(t, filepath.Join(repoRoot(t), ".github/workflows/deploy-pr-preview.yml"))
	for _, action := range []string{"opened", "synchronize", "closed"} {
		t.Run(action, func(t *testing.T) {
			pr := docsPullRequest(action, false)
			uses, err := evaluate(wf, pr)
			if err != nil {
				t.Fatal(err)
			}
			for _, use := range uses {
				if use.OIDCRepo != "" && use.OIDCRepo != pr.Repository {
					t.Errorf("OIDC token repository %s; the caller repository is %s", use.OIDCRepo, pr.Repository)
				}
				if use.StatusRepo != "" && (use.StatusRepo != pr.Repository || use.StatusSHA != pr.HeadSHA) {
					t.Errorf("status write targeted %s@%s; the pull request head is %s@%s", use.StatusRepo, use.StatusSHA, pr.Repository, pr.HeadSHA)
				}
				if use.LabeledRepo != "" && (use.LabeledRepo != pr.Repository || use.PullNumber != pr.Number) {
					t.Errorf("pull request write targeted %s#%d; the event is %s#%d", use.LabeledRepo, use.PullNumber, pr.Repository, pr.Number)
				}
				if actedOnOtherRepo(use, "grafana/writers-toolkit") || actedOnOtherRepo(use, "octo-org/other") {
					t.Errorf("token for %s acted on a different repository via %s", pr.Repository, use.Uses)
				}
			}
			assertNoPrivilegedUse(t, uses)
		})
	}
}

func TestDeployPreviewForkAndUnrelatedPathsDoNotRun(t *testing.T) {
	wf := loadWorkflow(t, filepath.Join(repoRoot(t), ".github/workflows/deploy-pr-preview.yml"))
	forkUses, err := evaluate(wf, docsPullRequest("synchronize", true))
	if err != nil {
		t.Fatal(err)
	}
	assertNoPrivilegedUse(t, forkUses)

	other, err := evaluate(wf, docsPullRequest("opened", false, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("preview workflow ran for a pull request that does not change docs/sources: %+v", other)
	}
}

func TestCalledWorkflowCannotRaisePermissions(t *testing.T) {
	caller := permissionSet{
		"contents": permRead,
	}
	requested := permissionSet{
		"contents":      permRead,
		"id-token":      permWrite,
		"pull-requests": permWrite,
		"statuses":      permWrite,
	}
	if !violatesMax(requested, caller) {
		t.Fatal("a called workflow was allowed to raise id-token, pull-requests, and statuses above the caller")
	}
}

func TestPinnedReusableWorkflowIsNotTheMovingBranch(t *testing.T) {
	pinned := []byte(`
name: Deploy pr preview
on:
  pull_request:
    types: [opened, synchronize, closed]
    paths: ["docs/sources/**"]
permissions: {}
jobs:
  deploy-pr-preview:
    permissions:
      contents: read
      id-token: write
      pull-requests: write
      statuses: write
    if: "!github.event.pull_request.head.repo.fork"
    uses: grafana/writers-toolkit/.github/workflows/deploy-preview.yml@0123456789abcdef0123456789abcdef01234567
    with:
      sha: example
`)
	wf, err := parseWorkflow(pinned)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := evaluate(wf, docsPullRequest("opened", false))
	if err != nil {
		t.Fatal(err)
	}
	assertNoPrivilegedUse(t, uses)
}

func TestPullRequestWorkflowsDoNotGrantWritersToolkitAPrivilegedToken(t *testing.T) {
	root := filepath.Join(repoRoot(t), ".github/workflows")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(root, name)
		wf := loadWorkflow(t, path)
		for _, eventName := range []string{"pull_request", "pull_request_target"} {
			filter, ok := wf.Events[eventName]
			if !ok {
				continue
			}
			pr := triggeringPullRequest(eventName, filter)
			uses, err := evaluate(wf, pr)
			if err != nil {
				t.Fatal(err)
			}
			for _, use := range uses {
				if use.privileged() {
					t.Errorf("%s grants a moving ref privileged caller permissions on %s %s: %s id-token=%s pull-requests=%s statuses=%s",
						name, eventName, pr.Action, use.Uses,
						use.Permissions.get("id-token"), use.Permissions.get("pull-requests"), use.Permissions.get("statuses"))
				}
			}
		}
	}
}

func triggeringPullRequest(eventName string, filter *eventFilter) pullRequest {
	action := "opened"
	if len(filter.Types) > 0 {
		action = filter.Types[0]
	}
	base := "main"
	if len(filter.Branches) > 0 {
		base = concreteFilter(filter.Branches[0])
	}
	file := "README.md"
	if len(filter.Paths) > 0 {
		for _, pattern := range filter.Paths {
			if strings.HasPrefix(pattern, "!") {
				continue
			}
			file = concreteFilter(pattern)
			break
		}
	}
	return pullRequest{
		Event:      eventName,
		Action:     action,
		Base:       base,
		Files:      []string{file},
		Fork:       false,
		Repository: callerRepository,
		HeadSHA:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Number:     7,
		Title:      "Update docs",
	}
}

func concreteFilter(pattern string) string {
	pattern = strings.TrimPrefix(pattern, "!")
	replacer := strings.NewReplacer("**", "example", "*", "example", "?", "", "[", "", "]", "", "+", "")
	value := replacer.Replace(pattern)
	value = strings.Trim(value, "/")
	if value == "" || strings.HasSuffix(pattern, "/") || strings.HasSuffix(pattern, "**") {
		if !strings.Contains(value, ".") {
			value = strings.TrimSuffix(value, "/") + "/file.md"
		}
	}
	return strings.TrimPrefix(value, "/")
}
