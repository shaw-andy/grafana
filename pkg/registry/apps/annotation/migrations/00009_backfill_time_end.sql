-- +goose Up
-- +goose StatementBegin
-- Backfill time_end for rows where it is NULL
DO $$
DECLARE
    rows_updated integer;
BEGIN
    LOOP
        UPDATE annotations
        SET time_end = time
        WHERE (namespace, name, time) IN (
            SELECT namespace, name, time
            FROM annotations
            WHERE time_end IS NULL
            LIMIT 5000
        );
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        EXIT WHEN rows_updated = 0;
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
