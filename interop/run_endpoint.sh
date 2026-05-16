#!/usr/bin/env bash
set -euo pipefail

role="${ROLE:-}"
testcase="${TESTCASE:-}"

supports_testcase() {
  case "$1" in
    handshake|transfer)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

if [ -n "${testcase}" ] && ! supports_testcase "${testcase}"; then
  echo "unsupported TESTCASE=${testcase}" >&2
  exit 127
fi

case "${role}" in
server)
  /setup.sh || true
  exec /usr/local/bin/deerquic-interop server \
    --cert /certs/cert.pem \
    --key /certs/priv.key
  ;;
client)
  /wait-for-it.sh sim:57832 -s -t 30 -- true
  exec /usr/local/bin/deerquic-interop client \
    --host server \
    --port 443
  ;;
*)
  echo "unsupported ROLE=${role}" >&2
  exit 1
  ;;
esac
