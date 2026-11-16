#!/bin/bash
set -euo pipefail
RAW_NAME="${WORKFLOW_REF}"
REF_SHA=$(echo -n "$RAW_NAME" | sed -E 's|^[^/]*/[^/]*/||' | sed -E 's/@.*//' | sha256sum | awk '{print $1}')
printf '%s\n' "$REF_SHA"
