package repo

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"agentflow/internal/domain"
)

// SidebarRunMeta is the cheap run header the conversation history needs to
// name and label a shared SOP run session. Decorating the whole list from
// batched reads keeps the history endpoint's query count flat: per-session
// RunState lookups once made long histories slow and transferred node graphs
// the sidebar never shows.
type SidebarRunMeta struct {
	Status            string
	WorkflowID        string
	Kind              string
	WorkflowName      string
	IssueID           string
	IssueNumber       int
	ResponsibleUserID int64
	// Input is the head of the task text the run was started with; it names a
	// run that serves no requirement.
	Input     string
	CreatedAt time.Time
}

// sidebarRunInputChars bounds how much task text the list reads per run.
const sidebarRunInputChars = 300

// SidebarRunMetas loads those headers for the listed runs.
func (r *RunsRepo) SidebarRunMetas(ids []string) map[string]SidebarRunMeta {
	out := make(map[string]SidebarRunMeta, len(ids))
	if len(ids) == 0 {
		return out
	}
	nameExpr := "json_extract(snapshot, '$.name')"
	if r.isMySQL() {
		nameExpr = "JSON_UNQUOTE(JSON_EXTRACT(snapshot, '$.name'))"
	}
	for start := 0; start < len(ids); start += 500 {
		var rows []struct {
			ID         string
			Status     string
			WorkflowID *string
			Kind       *string
			Workflow   *string
			Context    []byte
			Input      *string
			Created    *time.Time
		}
		err := r.DB.Table("runs").
			Select(fmt.Sprintf("id, status, workflow_id, kind, %s AS workflow, execution_context AS context, SUBSTR(input, 1, %d) AS input, created_at AS created", nameExpr, sidebarRunInputChars)).
			Where("id IN ?", ids[start:min(start+500, len(ids))]).
			Scan(&rows).Error
		if err != nil {
			log.Printf("sidebar run meta read failed: %v", err)
			return out
		}
		for _, row := range rows {
			meta := SidebarRunMeta{Status: row.Status}
			if row.Workflow != nil {
				meta.WorkflowName = *row.Workflow
			}
			var ctx domain.TelemetryContext
			if len(row.Context) > 0 {
				_ = json.Unmarshal(row.Context, &ctx)
			}
			meta.IssueID = ctx.IssueID
			meta.IssueNumber = ctx.IssueNumber
			meta.ResponsibleUserID = ctx.ResponsibleUserID
			if row.WorkflowID != nil {
				meta.WorkflowID = *row.WorkflowID
			}
			if row.Kind != nil {
				meta.Kind = *row.Kind
			}
			if row.Input != nil {
				meta.Input = *row.Input
			}
			if row.Created != nil {
				meta.CreatedAt = *row.Created
			}
			out[row.ID] = meta
		}
	}
	return out
}
