package repo

import "log"

// AssistantSessionMessageCounts reports persisted message counts so the history
// list can tell an unused SOP run conversation from one that already holds a
// discussion, without transferring transcripts. The list projection strips
// messages, so the count has to come from the stored payload.
func (r *AssistantRepo) AssistantSessionMessageCounts(ids []string) map[string]int {
	out := make(map[string]int, len(ids))
	if len(ids) == 0 {
		return out
	}
	expr := "COALESCE(json_array_length(payload, '$.messages'), 0)"
	if r.isMySQL() {
		expr = "COALESCE(JSON_LENGTH(JSON_EXTRACT(payload, '$.messages')), 0)"
	}
	for start := 0; start < len(ids); start += 500 {
		var rows []struct {
			ID    string
			Total int
		}
		err := r.DB.Table("assistant_sessions").Select("id, "+expr+" AS total").
			Where("id IN ?", ids[start:min(start+500, len(ids))]).Scan(&rows).Error
		if err != nil {
			log.Printf("assistant message count read failed: %v", err)
			return out
		}
		for _, row := range rows {
			out[row.ID] = row.Total
		}
	}
	return out
}
