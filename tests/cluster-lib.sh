# Helpers for a local multi-process Royak cluster (sourced by the cluster
# test scripts). Every node gets its own directory, state file, data dir and
# HOME; nodes talk over signed TLS node RPC with a per-run cluster secret.
#
# Cleanup only touches what this run created: the node processes it started
# and the containers/networks labelled with this run's cluster id.

: "${BIN:=$PWD/target/release/royak}"
: "${BASE_PORT:=47700}"
: "${INTERVAL:=2}"
NODES="${NODES:-1 2 3}"

cport() { echo $((BASE_PORT + $1)); }
iport() { echo $((BASE_PORT + 80 + $1)); }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

peers_for() {
    local self=$1 out="" i
    for i in $NODES; do
        [ "$i" = "$self" ] && continue
        out="$out${out:+,}$i@127.0.0.1:$(cport "$i")"
    done
    echo "$out"
}

# cluster_init WORKDIR — tokens (admin + viewer), cluster secret, sealing key.
cluster_init() {
    WORK=$1
    mkdir -p "$WORK"
    ADMIN_TOKEN=$(rand_hex 24)
    VIEW_TOKEN=$(rand_hex 24)
    umask 077
    printf '%s,root,u1,"system:masters"\n%s,vera,u2,"viewers"\n' "$ADMIN_TOKEN" "$VIEW_TOKEN" > "$WORK/tokens.csv"
    umask 022
    export ROYAK_TOKEN_FILE="$WORK/tokens.csv"
    export ROYAK_CLUSTER_SECRET="ci-$(rand_hex 24)"
    export ROYAK_SECRET_KEY="$(rand_hex 16)"
    export ADMIN_TOKEN VIEW_TOKEN WORK
}

# start_node ID [extra watch args...] — node 1 carries --bootstrap, which only
# initialises a brand-new Raft log (ignored on restart).
start_node() {
    local i=$1 d="$WORK/n$1"; shift
    [ "$i" = "${BOOTSTRAP_NODE:-1}" ] && set -- --bootstrap "$@"
    mkdir -p "$d/home" "$d/data"
    (
        cd "$d" || exit 1
        HOME="$d/home" ROYAK_DATA_DIR="$d/data" ROYAK_STATE="$d/state.json" \
        ROYAK_NODE_NAME="ci-n$i" ROYAK_ADVERTISE_ADDR="127.0.0.1:$(cport "$i")" \
        nohup "$BIN" watch --tls --port "$(cport "$i")" --ingress-port "$(iport "$i")" \
            --interval "$INTERVAL" --node-id "$i" --peers "$(peers_for "$i")" "$@" \
            >> "$d/server.log" 2>&1 &
        echo $! > "$d/pid"
    )
    local n
    for n in $(seq 1 150); do
        curl -sk -m 2 -o /dev/null "https://127.0.0.1:$(cport "$i")/healthz" && return 0
        sleep 0.2
    done
    echo "node $i did not come up"; tail -20 "$d/server.log"; return 1
}

# stop_node ID [SIGNAL] — signal and wait for exit.
stop_node() {
    local d="$WORK/n$1" sig=${2:-TERM} p n
    p=$(cat "$d/pid" 2>/dev/null) || return 0
    kill -"$sig" "$p" 2>/dev/null || return 0
    for n in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done
    echo "node $1 did not exit"; return 1
}

# api ID METHOD PATH [BODY-FILE] [TOKEN] [CONTENT-TYPE] — body, then "HTTP <code>".
api() {
    local i=$1 m=$2 p=$3 body=${4:-} tok=${5:-$ADMIN_TOKEN} ct=${6:-application/yaml}
    if [ -n "$body" ]; then
        curl -sk -m 25 -w '\nHTTP %{http_code}\n' -X "$m" -H "Authorization: Bearer $tok" \
            -H "Content-Type: $ct" --data-binary @"$body" "https://127.0.0.1:$(cport "$i")$p"
    else
        curl -sk -m 25 -w '\nHTTP %{http_code}\n' -X "$m" -H "Authorization: Bearer $tok" \
            "https://127.0.0.1:$(cport "$i")$p"
    fi
}
code_of() { tail -1 | awk '{print $2}'; }

# leader [WAIT_SECS] — id of the node reporting a quorum-confirmed leadership.
leader() {
    local end=$((SECONDS + ${1:-30})) i
    while [ $SECONDS -lt $end ]; do
        for i in $NODES; do
            [ -f "$WORK/n$i/pid" ] && kill -0 "$(cat "$WORK/n$i/pid")" 2>/dev/null || continue
            if curl -sk -m 2 -H "Authorization: Bearer $ADMIN_TOKEN" \
                "https://127.0.0.1:$(cport "$i")/royak/v1/raft/status" 2>/dev/null \
                | grep -q '"leaderConfirmed": *true'; then
                echo "$i"; return 0
            fi
        done
        sleep 0.3
    done
    return 1
}

# running_in NS [extra docker filter] — "name node" per running pod.
running_in() {
    docker ps --filter "label=royak.namespace=$1" --filter status=running ${2:+--filter "$2"} \
        --format '{{.Names}} {{.Label "royak.node"}}'
}

cluster_cleanup() {
    local i cid
    for i in $NODES; do stop_node "$i" KILL >/dev/null 2>&1 || true; done
    for cid in $(docker ps -a --filter "label=royak.node" --format '{{.Label "royak.cluster"}} {{.Label "royak.node"}}' \
                 | awk '$2 ~ /^ci-n[0-9]+$/ {print $1}' | sort -u); do
        [ "$cid" = "${CLUSTER_ID:-}" ] || continue
        docker ps -aq --filter "label=royak.cluster=$cid" | xargs -r docker rm -f >/dev/null 2>&1 || true
        docker network ls -q --filter "label=royak.cluster=$cid" | xargs -r docker network rm >/dev/null 2>&1 || true
    done
}
