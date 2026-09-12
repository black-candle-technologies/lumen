CREATE INDEX audit_workspace_run_sequence_idx
ON audit_events(workspace_id, json_extract(payload_json, '$.run_id'), sequence);
