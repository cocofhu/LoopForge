package domain

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRestoreMaskedMCPSecrets(t *testing.T) {
	incoming := MCPServerDefinition{
		Headers:     map[string]string{"Authorization": MaskedSecretValue, "X-Trace": "new"},
		Environment: map[string]string{"API_TOKEN": MaskedSecretValue, "NEW_SECRET": MaskedSecretValue, "LOG_LEVEL": "debug"},
	}
	existing := MCPServerDefinition{
		Headers:     map[string]string{"Authorization": "Bearer stored", "X-Trace": "old"},
		Environment: map[string]string{"API_TOKEN": "stored-token"},
	}
	RestoreMaskedMCPSecrets(&incoming, existing)
	if got := incoming.Headers; len(got) != 2 || got["Authorization"] != "Bearer stored" || got["X-Trace"] != "new" {
		t.Fatalf("headers = %v", got)
	}
	if got := incoming.Environment; len(got) != 2 || got["API_TOKEN"] != "stored-token" || got["LOG_LEVEL"] != "debug" {
		t.Fatalf("masked value without stored counterpart must be dropped: %v", got)
	}
	if _, ok := incoming.Environment["NEW_SECRET"]; ok {
		t.Fatal("NEW_SECRET must not be saved as the mask literal")
	}

	empty := MCPServerDefinition{}
	RestoreMaskedMCPSecrets(&empty, existing)
	if empty.Headers != nil || empty.Environment != nil {
		t.Fatalf("nil maps must stay nil: %#v", empty)
	}
}

func TestPublicMCPServersMasksHeadersWithoutMutatingInput(t *testing.T) {
	in := []MCPServerDefinition{
		{
			ID:          "a",
			Headers:     map[string]string{"Authorization": "Bearer x", "X-Ref": "${secret:GH}", "X-Empty": ""},
			Environment: map[string]string{"github_token": "t", "session_id": "s", "REGION": "ap"},
		},
		{ID: "b"},
	}
	out := PublicMCPServers(in)
	if len(out) != 2 || out[0].ID != "a" || out[1].ID != "b" {
		t.Fatalf("out = %#v", out)
	}
	h := out[0].Headers
	if h["Authorization"] != MaskedSecretValue || h["X-Ref"] != "${secret:GH}" || h["X-Empty"] != "" {
		t.Fatalf("headers = %v", h)
	}
	env := out[0].Environment
	if env["github_token"] != MaskedSecretValue || env["session_id"] != MaskedSecretValue || env["REGION"] != "ap" {
		t.Fatalf("environment = %v", env)
	}
	if in[0].Headers["Authorization"] != "Bearer x" || in[0].Environment["github_token"] != "t" {
		t.Fatalf("input mutated: %#v", in[0])
	}
	if out[1].Headers != nil || out[1].Environment != nil {
		t.Fatalf("empty maps must stay nil: %#v", out[1])
	}
	if got := PublicMCPServers(nil); len(got) != 0 {
		t.Fatalf("nil input = %#v", got)
	}
}

func TestValidateVerificationGates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gates   []VerificationGate
		wantErr []string
	}{
		{name: "nil", gates: nil},
		{name: "all valid", gates: []VerificationGate{
			{ID: "test", Commands: []string{"go test ./..."}, ExecutionScope: ExecutionScopeRun},
			{ID: "git", Commands: []string{"git diff --quiet"}, ExecutionScope: " " + ExecutionScopeRepositories + " "},
			{ID: "human", Mode: "manual"},
			{ID: "manual-commands", Mode: " Manual ", Commands: []string{"make lint"}},
			{ID: "blank", Commands: []string{"  ", ""}},
		}},
		{name: "first error wins", gates: []VerificationGate{
			{ID: "ok", Mode: "manual"},
			{ID: "bad-scope", Commands: []string{"make"}, ExecutionScope: "everywhere"},
			{ID: "bad-mode", Mode: "shell"},
		}, wantErr: []string{"bad-scope", "invalid executionScope"}},
		{name: "invalid mode", gates: []VerificationGate{{ID: "bad-mode", Mode: "shell"}}, wantErr: []string{"bad-mode", "invalid mode"}},
		{name: "missing scope falls back to name", gates: []VerificationGate{{Name: "lint", Commands: []string{"make lint"}}}, wantErr: []string{"lint", "requires executionScope"}},
		{name: "missing scope unnamed", gates: []VerificationGate{{Commands: []string{"make lint"}}}, wantErr: []string{"unnamed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVerificationGates(tc.gates)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestSafeWorkspaceRelPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"a", true},
		{"a/b.txt", true},
		{".agentflow/inputs/x.md", true},
		{"..foo", true},
		{"", false},
		{".", false},
		{"..", false},
		{"../x", false},
		{"/abs", false},
		{`a\b`, false},
		{"a/../b", false},
		{"a/./b", false},
		{"a//b", false},
		{"a/", false},
		{"a/..", false},
	} {
		if got := SafeWorkspaceRelPath(tc.path); got != tc.want {
			t.Errorf("SafeWorkspaceRelPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestRunnerCapabilityVersionGates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		supports func(Runner) bool
		min      string
		below    string
	}{
		{"conversation workspace", Runner.SupportsConversationWorkspace, RunnerVersionConversationWorkspace, "0.7.9"},
		{"git ssh", Runner.SupportsGitSSH, RunnerVersionGitSSH, "0.9.2"},
		{"shared push", Runner.SupportsSharedPush, RunnerVersionSharedPush, "0.8.99"},
		{"workspace preparation", Runner.SupportsWorkspacePreparation, RunnerVersionWorkspacePreparation, "0.5.1"},
		{"align baseline", Runner.SupportsAlignBaseline, RunnerVersionAlignBaseline, "0.4.9"},
		{"integrate", Runner.SupportsIntegrate, RunnerVersionIntegrate, "0.3.12"},
		{"reported outputs", Runner.SupportsReportedOutputs, RunnerVersionReportedOutputs, "0.2.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range []struct {
				version string
				want    bool
			}{
				{tc.min, true},
				{"v" + tc.min, true},
				{" " + tc.min + " ", true},
				{"1.0", true},
				{tc.below, false},
				{"", false},
				{"dev", false},
				{tc.min + "-rc1", false},
			} {
				if got := tc.supports(Runner{RunnerVersion: v.version}); got != v.want {
					t.Errorf("version %q = %v, want %v", v.version, got, v.want)
				}
			}
		})
	}
	if !(Runner{RunnerVersion: "0.9"}).SupportsSharedPush() || (Runner{RunnerVersion: "0.9"}).SupportsGitSSH() {
		t.Fatal("missing patch segment must compare as zero")
	}
}

func TestPublicRunnersStripSessionMaterial(t *testing.T) {
	expires := time.Now()
	in := []Runner{{ID: "r1", Name: "mac", SessionTokenHash: "hash", SessionExpiresAt: &expires}, {ID: "r2"}}
	out := PublicRunners(in)
	if len(out) != 2 || out[0].ID != "r1" || out[0].Name != "mac" || out[1].ID != "r2" {
		t.Fatalf("out = %#v", out)
	}
	for _, r := range out {
		if r.SessionTokenHash != "" || r.SessionExpiresAt != nil {
			t.Fatalf("session material leaked: %#v", r)
		}
	}
	if in[0].SessionTokenHash != "hash" || in[0].SessionExpiresAt == nil {
		t.Fatal("input runner mutated")
	}
}

func TestRunnerInvocationGitSSHRemotes(t *testing.T) {
	for _, tc := range []struct {
		name string
		inv  *RunnerInvocation
		want []string
	}{
		{name: "nil invocation", inv: nil},
		{name: "no repositories", inv: &RunnerInvocation{}},
		{name: "only ssh repositories in order", inv: &RunnerInvocation{Repositories: []RunnerRepository{
			{CloneURL: "git@a:x.git", UseSSH: true},
			{CloneURL: "https://b/y.git"},
			{CloneURL: "git@c:z.git", UseSSH: true},
		}}, want: []string{"git@a:x.git", "git@c:z.git"}},
		{name: "legacy repository with ssh", inv: &RunnerInvocation{Repository: &RunnerRepository{CloneURL: "git@legacy:x.git", UseSSH: true}}, want: []string{"git@legacy:x.git"}},
		{name: "legacy repository without ssh", inv: &RunnerInvocation{Repository: &RunnerRepository{CloneURL: "https://legacy/x.git"}}},
		{name: "legacy ignored when repositories set", inv: &RunnerInvocation{
			Repository:   &RunnerRepository{CloneURL: "git@legacy:x.git", UseSSH: true},
			Repositories: []RunnerRepository{{CloneURL: "https://b/y.git"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.inv.GitSSHRemotes(); !slices.Equal(got, tc.want) {
				t.Fatalf("remotes = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestIssueCompleted(t *testing.T) {
	for status, want := range map[string]bool{
		"done": true, "closed": true, " Completed ": true, "DONE": true,
		"": false, "open": false, "in_review": false, "cancelled": false,
	} {
		if got := (Issue{Status: status}).Completed(); got != want {
			t.Errorf("Completed(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestIssueAppendOperation(t *testing.T) {
	var nilIssue *Issue
	nilIssue.AppendOperation(IssueOperation{Action: "create"})

	issue := &Issue{}
	issue.AppendOperation(IssueOperation{Action: "   "})
	if len(issue.Operations) != 0 {
		t.Fatalf("blank action recorded: %#v", issue.Operations)
	}
	before := time.Now().UTC()
	issue.AppendOperation(IssueOperation{Action: " edit ", Actor: "alice"})
	if len(issue.Operations) != 1 || issue.Operations[0].Action != "edit" || issue.Operations[0].Actor != "alice" {
		t.Fatalf("operations = %#v", issue.Operations)
	}
	if at := issue.Operations[0].At; at.Before(before) || at.Location() != time.UTC {
		t.Fatalf("zero At must default to now in UTC, got %v", at)
	}
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	issue.AppendOperation(IssueOperation{Action: "close", At: fixed})
	if !issue.Operations[1].At.Equal(fixed) {
		t.Fatalf("explicit At overwritten: %v", issue.Operations[1].At)
	}

	capped := &Issue{}
	for i := 0; i < 205; i++ {
		capped.AppendOperation(IssueOperation{Action: "edit", Detail: strconv.Itoa(i), At: fixed})
	}
	if len(capped.Operations) != 200 || capped.Operations[0].Detail != "5" || capped.Operations[199].Detail != "204" {
		t.Fatalf("cap must keep newest 200: len=%d first=%q last=%q", len(capped.Operations), capped.Operations[0].Detail, capped.Operations[len(capped.Operations)-1].Detail)
	}
}

func TestIssueEffectiveRepositoryIDs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		issue Issue
		want  []string
	}{
		{name: "empty", issue: Issue{}, want: []string{}},
		{name: "legacy only", issue: Issue{RepositoryID: " r1 "}, want: []string{"r1"}},
		{name: "list first then legacy", issue: Issue{RepositoryIDs: []string{"r2", "r3"}, RepositoryID: "r1"}, want: []string{"r2", "r3", "r1"}},
		{name: "dedupe and drop blanks", issue: Issue{RepositoryIDs: []string{"r1", " ", "r1 ", "r2"}, RepositoryID: "r2"}, want: []string{"r1", "r2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.issue.EffectiveRepositoryIDs(); !slices.Equal(got, tc.want) {
				t.Fatalf("ids = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestIssueWorkBranchForRepository(t *testing.T) {
	for _, tc := range []struct {
		name  string
		issue Issue
		repo  string
		want  string
	}{
		{name: "per-repository selection", issue: Issue{RepositoryBranches: map[string]string{"r1": " feature/a "}, BaseBranch: "legacy"}, repo: "r1", want: "feature/a"},
		{name: "per-repository map overrides legacy", issue: Issue{RepositoryBranches: map[string]string{}, BaseBranch: "legacy"}, repo: "r1", want: ""},
		{name: "project default repository", issue: Issue{BaseBranch: " legacy "}, repo: "r1", want: "legacy"},
		{name: "single matching repository", issue: Issue{RepositoryID: "r1", BaseBranch: "legacy"}, repo: "r1", want: "legacy"},
		{name: "single other repository", issue: Issue{RepositoryID: "r1", BaseBranch: "legacy"}, repo: "r2", want: ""},
		{name: "multiple repositories", issue: Issue{RepositoryIDs: []string{"r1", "r2"}, BaseBranch: "legacy"}, repo: "r1", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.issue.WorkBranchForRepository(tc.repo); got != tc.want {
				t.Fatalf("branch = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIssueHasIdentityBlock(t *testing.T) {
	var issue Issue
	if !issue.HasIdentityBlock("prefix\n" + issueIdentityMarker + "\n- id") {
		t.Fatal("marker not detected")
	}
	if issue.HasIdentityBlock("") || issue.HasIdentityBlock("需求身份") {
		t.Fatal("partial marker must not match")
	}
}

func TestRunWorkspaceStates(t *testing.T) {
	cleaned := time.Now()
	for _, tc := range []struct {
		name       string
		run        Run
		workspace  bool
		live       bool
		historical bool
	}{
		{name: "running workspace", run: Run{Kind: RunKindWorkspace, Status: "running"}, workspace: true, live: true},
		{name: "waiting workspace", run: Run{Kind: RunKindWorkspace, Status: "waiting"}, workspace: true, live: true},
		{name: "finished workspace", run: Run{Kind: RunKindWorkspace, Status: "succeeded"}, workspace: true},
		{name: "cancel requested workspace", run: Run{Kind: RunKindWorkspace, Status: "running", CancelRequested: true}, workspace: true},
		{name: "cleaned workspace", run: Run{Kind: RunKindWorkspace, Status: "running", WorkspaceCleanedAt: cleaned}, workspace: true},
		{name: "running sop", run: Run{Status: "running"}},
		{name: "retired group", run: Run{WorkflowSnapshot: WorkflowDefinition{CollaborationMode: "group"}}, historical: true},
		{name: "workspace is never a group", run: Run{Kind: RunKindWorkspace, WorkflowSnapshot: WorkflowDefinition{CollaborationMode: "group"}}, workspace: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.run.IsWorkspace(); got != tc.workspace {
				t.Errorf("IsWorkspace = %v", got)
			}
			if got := tc.run.LiveWorkspace(); got != tc.live {
				t.Errorf("LiveWorkspace = %v", got)
			}
			if got := tc.run.HistoricalGroup(); got != tc.historical {
				t.Errorf("HistoricalGroup = %v", got)
			}
		})
	}
}

func TestTerminalRunStatus(t *testing.T) {
	for status, want := range map[string]bool{
		"succeeded": true, "failed": true, " cancelled ": true,
		"running": false, "waiting": false, "": false, "FAILED": false,
	} {
		if got := TerminalRunStatus(status); got != want {
			t.Errorf("TerminalRunStatus(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestWorkflowGroupMembers(t *testing.T) {
	explicit := WorkflowDefinition{GroupMembers: []string{"pm", "dev"}, Nodes: []WorkflowNode{{AgentID: "qa"}}}
	if got := explicit.GroupMemberIDs(); !slices.Equal(got, []string{"pm", "dev"}) {
		t.Fatalf("explicit members = %#v", got)
	}
	if explicit.HasGroupMember("qa") || !explicit.HasGroupMember("dev") {
		t.Fatal("explicit members must take precedence over nodes")
	}
	cleared := WorkflowDefinition{GroupMembers: []string{}, Nodes: []WorkflowNode{{AgentID: "qa"}}}
	if got := cleared.GroupMemberIDs(); len(got) != 0 || cleared.HasGroupMember("qa") {
		t.Fatalf("empty non-nil members must not fall back to nodes: %#v", got)
	}
	legacy := WorkflowDefinition{Nodes: []WorkflowNode{{AgentID: "dev"}, {}, {AgentID: "qa"}, {AgentID: "dev"}}}
	if got := legacy.GroupMemberIDs(); !slices.Equal(got, []string{"dev", "qa"}) {
		t.Fatalf("legacy members = %#v", got)
	}
	if legacy.HasGroupMember("") || !legacy.HasGroupMember("qa") {
		t.Fatal("legacy membership lookup")
	}
}

func TestIsWorkspaceCheckpointTransferOperation(t *testing.T) {
	for _, op := range []string{
		RunnerWorkspaceOperationCheckpointExport, RunnerWorkspaceOperationCheckpointRead, RunnerWorkspaceOperationCheckpointClose,
		RunnerWorkspaceOperationCheckpointUpload, RunnerWorkspaceOperationCheckpointAppend, RunnerWorkspaceOperationCheckpointCommit,
	} {
		if !IsWorkspaceCheckpointTransferOperation(op) {
			t.Errorf("%q must be a transfer operation", op)
		}
	}
	for _, op := range []string{"", RunnerWorkspaceOperationCheckpoint, RunnerWorkspaceOperationRestore, RunnerWorkspaceOperationWrite, " checkpoint_read"} {
		if IsWorkspaceCheckpointTransferOperation(op) {
			t.Errorf("%q must not be a transfer operation", op)
		}
	}
}

func TestResolveSandboxDriver(t *testing.T) {
	for _, tc := range []struct {
		driver, goos, want string
		wantErr            bool
	}{
		{driver: " docker ", goos: "windows", want: SandboxDriverDocker},
		{driver: "", goos: "linux", want: ""},
		{driver: SandboxDriverNative, goos: "darwin", want: SandboxDriverSeatbelt},
		{driver: " native ", goos: " Linux ", want: SandboxDriverBwrap},
		{driver: SandboxDriverNative, goos: "", want: SandboxDriverNative},
		{driver: SandboxDriverNative, goos: "windows", wantErr: true},
	} {
		got, err := ResolveSandboxDriver(tc.driver, tc.goos)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ResolveSandboxDriver(%q, %q) = %q, %v; want %q, err=%v", tc.driver, tc.goos, got, err, tc.want, tc.wantErr)
		}
		if tc.wantErr && (err == nil || !strings.Contains(err.Error(), tc.goos)) {
			t.Errorf("error must name the unsupported OS: %v", err)
		}
	}
}

func TestNormalizeAgentCLIProtocol(t *testing.T) {
	for _, tc := range []struct {
		kind, protocol, want string
	}{
		{"agy", AgentCLIProtocolChat, AgentCLIProtocolChat},
		{"agy", "unknown", AgentCLIProtocolGemini},
		{" zcode ", " " + AgentCLIProtocolResponses + " ", AgentCLIProtocolResponses},
		{"zcode", "", AgentCLIProtocolMessages},
		{"opencode", AgentCLIProtocolGemini, AgentCLIProtocolChat},
		{"codex", AgentCLIProtocolChat, ""},
		{"", "", ""},
	} {
		if got := NormalizeAgentCLIProtocol(tc.kind, tc.protocol); got != tc.want {
			t.Errorf("NormalizeAgentCLIProtocol(%q, %q) = %q, want %q", tc.kind, tc.protocol, got, tc.want)
		}
	}
}

func TestSmallIdentityPredicates(t *testing.T) {
	for id, want := range map[string]bool{BaselinePromoteIssueID: true, " " + BaselinePromoteIssueID + " ": true, "": false, "issue-1": false} {
		if got := IsBaselinePromoteIssueID(id); got != want {
			t.Errorf("IsBaselinePromoteIssueID(%q) = %v", id, got)
		}
	}
	for role, want := range map[string]bool{PlatformRoleAdmin: true, " ADMIN ": true, "": false, "member": false} {
		if got := IsPlatformAdmin(User{PlatformRole: role}); got != want {
			t.Errorf("IsPlatformAdmin(%q) = %v", role, got)
		}
	}
}

func TestKnowledgeSettingsHelpers(t *testing.T) {
	settings := KnowledgeSettings{Enabled: true, URL: "https://kb", Token: " secret "}
	public := settings.Public()
	if public.Token != "" || !public.TokenConfigured || public.URL != "https://kb" {
		t.Fatalf("public = %#v", public)
	}
	if settings.Token != " secret " {
		t.Fatal("Public must not mutate the receiver")
	}
	if blank := (KnowledgeSettings{Token: "  "}).Public(); blank.TokenConfigured {
		t.Fatal("whitespace token must not count as configured")
	}

	for _, tc := range []struct {
		name string
		s    KnowledgeSettings
		want bool
	}{
		{"ready", settings, true},
		{"disabled", KnowledgeSettings{URL: "https://kb", Token: "t"}, false},
		{"blank url", KnowledgeSettings{Enabled: true, URL: " ", Token: "t"}, false},
		{"blank token", KnowledgeSettings{Enabled: true, URL: "https://kb", Token: " "}, false},
	} {
		if got := tc.s.Ready(); got != tc.want {
			t.Errorf("%s: Ready = %v", tc.name, got)
		}
	}

	scoped := KnowledgeSettings{DefaultSources: []string{"d"}, ProjectSources: map[string][]string{"p1": {"a", "b"}, "p2": {}}}
	for _, tc := range []struct {
		project string
		want    []string
	}{
		{"p1", []string{"a", "b"}},
		{" p1 ", []string{"a", "b"}},
		{"p2", []string{}},
		{"p3", []string{"d"}},
	} {
		if got := scoped.SourcesForProject(tc.project); !slices.Equal(got, tc.want) {
			t.Errorf("SourcesForProject(%q) = %#v, want %#v", tc.project, got, tc.want)
		}
	}
	if got := (KnowledgeSettings{}).SourcesForProject("p1"); got != nil {
		t.Fatalf("unrestricted settings = %#v", got)
	}
}
