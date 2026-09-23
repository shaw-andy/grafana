-- +goose Up
ALTER TABLE annotations ALTER COLUMN time_end SET NOT NULL;
DROP INDEX IF EXISTS idx_time_end;
DROP INDEX IF EXISTS idx_dashboard;
CREATE INDEX idx_dashboard_range ON annotations (namespace, dashboard_uid, panel_id, time_end DESC, time DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_dashboard_range;
CREATE INDEX idx_dashboard ON annotations (namespace, dashboard_uid, panel_id, time);
CREATE INDEX idx_time_end ON annotations (namespace, time_end) WHERE time_end IS NOT NULL;
ALTER TABLE annotations ALTER COLUMN time_end DROP NOT NULL;
