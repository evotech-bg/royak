# Invoked as /bin/sh -c SCRIPT royak-probe TIMEOUT COMMAND [ARG...].
# A private session keeps the watchdog's process-group signal inside this
# probe, not the application or another exec. No writable filesystem is needed.
set +m
seconds=$1
shift
case "$seconds" in ''|*[!0-9]*) exit 125;; esac
[ "$seconds" -gt 0 ] && [ "$#" -gt 0 ] || exit 125
command -v setsid >/dev/null 2>&1 || exit 125
command -v sh >/dev/null 2>&1 || exit 125
command -v sleep >/dev/null 2>&1 || exit 125

# Job control is disabled, so this new background child is not already a
# process-group leader: setsid does not fork away from the PID we wait for.
setsid sh -c '
    seconds=$1
    shift
    # Verify isolation before starting user code. The fixed shell name has no
    # spaces; /proc is required rather than guessing a process group.
    read -r pid comm state parent group rest < /proc/$$/stat || exit 125
    [ "$pid" = "$group" ] || exit 125
    supervisor=$$
    (
        # A killed timer shell used to orphan its sleep under application PID 1.
        # Install the trap before forking and reap even when cancellation races
        # with the fork/assignment or interrupts wait.
        cancelled=0
        sleeper=
        cancel_timer() {
            cancelled=1
            # KILL the owned timer child, not user code. A flag-only trap can
            # arrive immediately before wait and leave a full timeout sleep.
            [ -z "$sleeper" ] || kill -KILL "$sleeper" 2>/dev/null || :
        }
        trap cancel_timer TERM
        sleep "$seconds" &
        sleeper=$!
        if [ "$cancelled" = 0 ]; then wait "$sleeper" 2>/dev/null || :; fi
        if [ "$cancelled" = 1 ]; then
            cancel_timer
            wait "$sleeper" 2>/dev/null || :
            exit 0
        fi
        # The Dash kill builtin does not accept -- here; the explicit signal
        # already disambiguates this internally-derived negative process group.
        kill -KILL "-$supervisor"
    ) &
    watchdog=$!
    "$@" &
    child=$!
    wait "$child"
    result=$?
    # The session leader stays alive until the watchdog is cancelled/reaped,
    # preventing its numeric process-group ID from being reused meanwhile.
    trap "" TERM
    kill -TERM "-$supervisor" 2>/dev/null || :
    wait "$watchdog" 2>/dev/null || :
    exit "$result"
' royak-probe-session "$seconds" "$@" &
session=$!
wait "$session"
result=$?
# The supervisor has reaped its children on normal completion. Finish any
# probe descendants that ignored TERM without touching the application or
# another exec. Timed-out/orphaned descendants are reaped by Docker's init.
kill -KILL "-$session" 2>/dev/null || :
exit "$result"
