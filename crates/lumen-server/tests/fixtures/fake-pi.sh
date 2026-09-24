#!/bin/sh
# Fake Pi RPC subprocess for session-supervisor tests.
#
# Speaks the real Pi RPC wire shapes (see phase-0 pi_supervisor.rs):
#   host -> pi : {"command":"<name>", ...params}   (JSONL on stdin)
#   pi -> host : {"type":"<event>", ...camelCase}  (JSONL on stdout)
#
# Modes (first argv):
#   (none)     read stdin; answer prompts with message_end + agent_settled;
#              answer get_state with a response carrying {"sessionId": ...}
#   evil       answer get_state, then emit an unmediated
#              tool_execution_start for "bash", then idle
#   garbage    answer get_state, then emit malformed lines, then idle
#   flood      answer get_state, then emit one line longer than the
#              test's max_line_bytes, then idle
#   exit-fast  exit 3 immediately (spawn must fail: no reference possible)
#   exit-slow  answer get_state, then exit 3 (post-spawn death)
#   no-state   never answer get_state (tests spawn failure on missing ref)
set -u

mode="${1:-}"
n=0

emit() {
  printf '%s\n' "$1"
}

# Answer one get_state on stdin, then return. Used by fault modes so the
# spawn's reference acquisition succeeds before the fault is emitted.
answer_get_state_once() {
  while IFS= read -r line; do
    case "$line" in
      *'"command":"get_state"'*)
        id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
        emit "{\"type\":\"response\",\"id\":\"$id\",\"command\":\"get_state\",\"success\":true,\"data\":{\"sessionId\":\"fake-pi-$mode\"}}"
        return 0
        ;;
    esac
  done
  return 1
}

case "$mode" in
  evil)
    answer_get_state_once
    emit '{"type":"tool_execution_start","toolCallId":"c1","toolName":"bash","args":{"command":"id"}}'
    sleep 30
    ;;
  garbage)
    answer_get_state_once
    i=0
    while [ "$i" -lt 10 ]; do
      printf 'this is not json\n'
      i=$((i + 1))
    done
    sleep 30
    ;;
  flood)
    answer_get_state_once
    i=0
    while [ "$i" -lt 8192 ]; do
      printf 'x'
      i=$((i + 1))
    done
    printf '\n'
    sleep 30
    ;;
  exit-fast)
    exit 3
    ;;
  exit-slow)
    answer_get_state_once
    sleep 1
    exit 3
    ;;
  no-state)
    # Answer everything except get_state; exit on stdin EOF.
    while IFS= read -r line; do
      case "$line" in
        *'"command":"prompt"'*)
          emit '{"type":"message_end"}'
          emit '{"type":"agent_settled"}'
          ;;
      esac
    done
    ;;
  *)
    # Default: minimal RPC loop. Respond to prompts and get_state;
    # exit on stdin EOF.
    while IFS= read -r line; do
      case "$line" in
        *'"command":"prompt"'*)
          emit '{"type":"message_end"}'
          emit '{"type":"agent_settled"}'
          ;;
        *'"command":"get_state"'*)
          n=$((n + 1))
          # Echo back the request id so the host can correlate.
          id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
          emit "{\"type\":\"response\",\"id\":\"$id\",\"command\":\"get_state\",\"success\":true,\"data\":{\"sessionId\":\"fake-pi-$n\"}}"
          ;;
        *'"command":"abort"'*)
          id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
          emit "{\"type\":\"response\",\"id\":\"$id\",\"command\":\"abort\",\"success\":true}"
          ;;
        *'"command":"set_model"'*)
          id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
          emit "{\"type\":\"response\",\"id\":\"$id\",\"command\":\"set_model\",\"success\":true}"
          ;;
      esac
    done
    ;;
esac
