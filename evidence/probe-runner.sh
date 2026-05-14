#!/usr/bin/env bash
# evidence/probe-runner.sh
#
# Runs all registered probes, aggregates results into evidence.json,
# then optionally signs the canonical bytes with the host SSH ed25519 key
# and publishes the host public key alongside.
#
# Arguments:
#   $1 - output directory (default: /var/lib/nixfleet-compliance)
#   $2 - probe directory (contains executable probe scripts)
#   $3 - sign binary path (empty string = signing disabled)
#   $4 - host SSH ed25519 private key path (used when $3 non-empty)
#   $5 - "1" to publish host pubkey to <outdir>/evidence.host.pub, else "0"
set -euo pipefail

output_dir="${1:-/var/lib/nixfleet-compliance}"
probe_dir="${2}"
sign_bin="${3:-}"
host_key="${4:-}"
publish_pubkey="${5:-0}"

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
      explicit_status=$(echo "$probe_output" | jq -r 'if has("compliant") then .compliant else empty end' 2>/dev/null || echo "")
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

# 0644: the JSON is operator-visible state. Only this service
# (running as root) writes; any user can read. compliance-check
# and downstream consumers (future runtime gate in nixfleet) rely
# on this — see #12.
chmod 0644 "${output_dir}/evidence.json"

# Optional: sign the JCS-canonical bytes of evidence.json with the host's
# SSH ed25519 key. Auditor verifies offline with `nixfleet-compliance-verify`.
# Best-effort: signing failures (missing key, wrong algorithm, etc.) log
# a warning but do not fail the collection -- the unsigned JSON is still
# useful operationally even if the auditor chain is unavailable.
# Stderr from the sign helper flows directly to the systemd journal so a
# failure is debuggable via `journalctl -u compliance-evidence-collector`.
if [ -n "$sign_bin" ] && [ -n "$host_key" ]; then
  if [ -r "$host_key" ]; then
    if "$sign_bin" \
         --evidence "${output_dir}/evidence.json" \
         --host-key "$host_key" \
         --out "${output_dir}/evidence.json.sig"; then
      chmod 0644 "${output_dir}/evidence.json.sig"
    else
      echo "WARNING: nixfleet-compliance-sign exited non-zero; evidence.json.sig removed." >&2
      rm -f "${output_dir}/evidence.json.sig"
    fi
  else
    echo "WARNING: host signing key $host_key not readable; evidence not signed." >&2
    ls -la "$host_key" >&2 || true
  fi
fi

# Optional: copy the host public key into the output dir so an auditor
# receives a self-contained verification bundle (evidence.json +
# evidence.json.sig + evidence.host.pub).
if [ "$publish_pubkey" = "1" ] && [ -n "$host_key" ]; then
  if [ -r "${host_key}.pub" ]; then
    install -m 0644 "${host_key}.pub" "${output_dir}/evidence.host.pub"
  else
    echo "WARNING: ${host_key}.pub not readable; evidence.host.pub not published." >&2
  fi
fi

echo "Evidence collected: ${compliant}/${total} controls compliant"
