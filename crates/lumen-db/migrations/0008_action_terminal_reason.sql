ALTER TABLE actions ADD COLUMN terminal_reason TEXT;

CREATE TRIGGER actions_terminal_reason_requires_terminal_state
BEFORE UPDATE OF terminal_reason ON actions
WHEN NEW.terminal_reason IS NOT NULL
     AND NEW.state NOT IN ('denied', 'succeeded', 'failed', 'cancelled', 'timed_out', 'unknown')
BEGIN
    SELECT RAISE(ABORT, 'terminal reason requires a terminal action state');
END;
