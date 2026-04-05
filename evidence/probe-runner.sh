#!/usr/bin/env bash
# evidence/probe-runner.sh
#
# Runs all registered probes, aggregates results into evidence.json.
# Called by the systemd timer via collector.nix.
#
# Arguments:
#   $1 — output directory (default: /var/lib/nixfleet-compliance)
#   $2 — probe directory (contains executable probe scripts)
set -euo pipefail

output_dir="${1:-/var/lib/nixfleet-compliance}"
probe_dir="${2}"
hostname=$(hostname)
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "$output_dir"

# Collect all probe results
controls="[]"
for probe in "$probe_dir"/*; do
  [ -x "$probe" ] || continue
  control_name=$(basename "$probe" | sed 's/^probe-//')

  # Read probe metadata (first line is JSON with control + articles)
  meta_file="${probe}.meta"
  if [ -f "$meta_file" ]; then
    meta=$(cat "$meta_file")
  else
    meta="{\"control\": \"${control_name}\", \"articles\": {}}"
  fi

  # Run probe, capture output
  if probe_output=$("$probe" 2>/dev/null); then
    # Validate probe output is valid JSON
    if ! echo "$probe_output" | jq empty >/dev/null 2>&1; then
      status="error"
      checks="{\"error\": \"probe output is not valid JSON\"}"
    else
      # Compliance status determination:
      # 1. If probe outputs a "compliant" boolean field, use it directly
      # 2. Otherwise, fall back to checking if any boolean is false
      explicit_status=$(echo "$probe_output" | jq -r '.compliant // empty' 2>/dev/null || echo "")
      if [ "$explicit_status" = "true" ]; then
        status="compliant"
      elif [ "$explicit_status" = "false" ]; then
        status="non-compliant"
      else
        # Fallback: any top-level false boolean = non-compliant
        status="compliant"
        has_false=$(echo "$probe_output" | jq '[to_entries[] | select(.value == false)] | length' 2>/dev/null || echo "0")
        if [ "${has_false:-0}" -gt 0 ]; then
          status="non-compliant"
        fi
      fi
      checks="$probe_output"
    fi
  else
    status="error"
    checks="{\"error\": \"probe exited with code $?\"}"
  fi

  # Build control entry
  entry=$(jq -n \
    --arg control "$control_name" \
    --arg status "$status" \
    --argjson articles "$(echo "$meta" | jq '.articles')" \
    --argjson checks "$checks" \
    '{control: $control, status: $status, framework_articles: $articles, checks: $checks}')

  controls=$(echo "$controls" | jq --argjson entry "$entry" '. + [$entry]')
done

# Compute overall status
total=$(echo "$controls" | jq 'length')
compliant=$(echo "$controls" | jq '[.[] | select(.status == "compliant")] | length')

# Build final evidence envelope
jq -n \
  --arg host "$hostname" \
  --arg timestamp "$timestamp" \
  --argjson controls "$controls" \
  --arg compliant "${compliant}/${total} controls compliant" \
  '{
    host: $host,
    timestamp: $timestamp,
    controls: $controls,
    overall: $compliant
  }' > "${output_dir}/evidence.json"

echo "Evidence collected: ${compliant}/${total} controls compliant"
