#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "${repo_root}"

readonly interop_runner_ref="${INTEROP_RUNNER_REF:-97319f8c0be2bc0be67b025522a64c9231018d37}"
readonly interop_peer_impl="${INTEROP_PEER_IMPL:-}"
readonly interop_peer_image="${INTEROP_PEER_IMAGE:-}"
readonly interop_testcases="${INTEROP_TESTCASES:-handshake,transfer}"
readonly interop_directions="${INTEROP_DIRECTIONS:-both}"
readonly interop_save_files="${INTEROP_SAVE_FILES:-1}"

log_root_input="${INTEROP_LOG_ROOT:-${repo_root}/.interop-logs/official}"
if [[ "${log_root_input}" != /* ]]; then
  log_root_input="${repo_root}/${log_root_input}"
fi
readonly log_root="${log_root_input}"
readonly runner_repo_url="https://github.com/quic-interop/quic-interop-runner"
readonly runner_dir="$(mktemp -d "${TMPDIR:-/tmp}/deerquic-interop-runner.XXXXXX")"

echo "Interop runner dir: ${runner_dir}"
echo "Log root: ${log_root}"

# Clone runner
git clone --depth 1 "${runner_repo_url}" "${runner_dir}"
cd "${runner_dir}"
if [ -n "${interop_runner_ref}" ]; then
  git fetch --depth 1 origin "${interop_runner_ref}"
  git checkout FETCH_HEAD
fi

# Build deerquic Docker image
echo "Building deerquic interop image..."
cd "${repo_root}"
cargo build --release --bin deerquic-interop
docker build -t deerquic-interop:latest -f interop/Dockerfile .

# Install runner Python dependencies
cd "${runner_dir}"
if [ -f requirements.txt ]; then
  pip3 install --quiet -r requirements.txt
fi

# Run interop tests
export CLIENT="${interop_peer_impl}"
export SERVER="${interop_peer_impl}"
export CLIENT_IMAGE="${interop_peer_image}"
export SERVER_IMAGE="${interop_peer_image}"
export IMPL_DEERQUIC="deerquic"
export IMPL_DEERQUIC="deerquic-interop:latest"
export TESTCASES="${interop_testcases}"
export DIRECTIONS="${interop_directions}"
export SAVE_FILES="${interop_save_files}"

# Make the runner aware of deerquic
cat > implementations_quic.json <<JSON
[
  {
    "name": "deerquic",
    "image": "deerquic-interop:latest",
    "url": "https://github.com/minhuw/deerquic",
    "role": "both"
  },
  {
    "name": "${interop_peer_impl}",
    "image": "${interop_peer_image}",
    "url": "",
    "role": "both"
  }
]
JSON

# Run subset of testcases
python3 run.py \
  --client "deerquic" \
  --server "${interop_peer_impl}" \
  --testcase "${interop_testcases}" \
  --log-dir "${log_root}/deerquic_client_${interop_peer_impl}_server" \
  --save-files "${interop_save_files}" \
  || true

python3 run.py \
  --client "${interop_peer_impl}" \
  --server "deerquic" \
  --testcase "${interop_testcases}" \
  --log-dir "${log_root}/${interop_peer_impl}_client_deerquic_server" \
  --save-files "${interop_save_files}" \
  || true

echo "Interop run complete. Logs at ${log_root}"
