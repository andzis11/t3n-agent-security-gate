#!/usr/bin/env bash
set -euo pipefail
cleanup() { unset T3N_API_KEY; }
trap cleanup EXIT INT TERM
if [[ -z "${T3N_API_KEY:-}" ]]; then
  [[ -t 0 ]] || { printf '%s\n' 'T3N_API_KEY is missing and no interactive terminal is available.' >&2; exit 2; }
  read -r -s -p 'T3N API key (input hidden): ' T3N_API_KEY
  printf '\n'
  export T3N_API_KEY
fi
[[ -n "$T3N_API_KEY" ]] || { printf '%s\n' 'No key entered.' >&2; exit 2; }
node src/t3n-invoke.js
