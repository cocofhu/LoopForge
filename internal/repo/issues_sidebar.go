package repo

import "log"

// SidebarIssue is the requirement identity shown next to a SOP run.
type SidebarIssue struct {
	Number int
	Title  string
}

// IssueSidebarIdentities loads only the requirement number and title, never
// the description or the comments.
func (r *IssuesRepo) IssueSidebarIdentities(ids []string) map[string]SidebarIssue {
	out := make(map[string]SidebarIssue, len(ids))
	if len(ids) == 0 {
		return out
	}
	for start := 0; start < len(ids); start += 500 {
		var rows []struct {
			ID     string
			Number int
			Title  string
		}
		err := r.DB.Table("issues").Select("id, number, title").
			Where("id IN ?", ids[start:min(start+500, len(ids))]).Scan(&rows).Error
		if err != nil {
			log.Printf("sidebar issue identity read failed: %v", err)
			return out
		}
		for _, row := range rows {
			out[row.ID] = SidebarIssue{Number: row.Number, Title: row.Title}
		}
	}
	return out
}
