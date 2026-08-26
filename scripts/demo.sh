#!/bin/sh
# Two-client offline demo against a local sqlite relay.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
go build -o /tmp/quietline-server ./cmd/server
go build -o /tmp/ql ./cmd/ql
rm -f /tmp/quietline-demo.db
QUIETLINE_DSN=sqlite:/tmp/quietline-demo.db QUIETLINE_LISTEN=127.0.0.1:8088 /tmp/quietline-server &
SPID=$!
trap 'kill $SPID 2>/dev/null || true' EXIT
i=0
while [ "$i" -lt 50 ]; do
  if wget -qO- http://127.0.0.1:8088/healthz >/dev/null 2>&1; then
    break
  fi
  i=$((i+1))
  sleep 0.1
done
rm -rf /tmp/ql-alice /tmp/ql-bob
QL_SERVER=http://127.0.0.1:8088
export QL_SERVER
QL_HOME=/tmp/ql-alice /tmp/ql register alice password1
QL_HOME=/tmp/ql-bob /tmp/ql register bob password1
QL_HOME=/tmp/ql-bob /tmp/ql send alice "hello from bob"
echo "-- alice recv --"
QL_HOME=/tmp/ql-alice /tmp/ql recv
echo "-- safety --"
QL_HOME=/tmp/ql-alice /tmp/ql safety bob
QL_HOME=/tmp/ql-bob /tmp/ql safety alice
