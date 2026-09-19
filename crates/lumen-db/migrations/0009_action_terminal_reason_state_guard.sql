CREATE TRIGGER actions_terminal_reason_prevents_nonterminal_state
BEFORE UPDATE OF state ON actions
WHEN OLD.terminal_reason IS NOT NULL
     AND NEW.state NOT IN ('denied', 'succeeded', 'failed', 'cancelled', 'timed_out', 'unknown')
BEGIN
    SELECT RAISE(ABORT, 'terminal reason requires a terminal action state');
END;
