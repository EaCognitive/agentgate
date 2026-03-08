#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-patent_exports/top5}"
mkdir -p "$OUT_DIR"/pdf "$OUT_DIR"/txt

# id|label|source_url
records=(
  "US12549574B1|mcp_server_remediation|https://api.uspto.gov/api/v1/download/applications/19267471/9570e4ba-ca31-40f8-b9db-6cb6910074f5/files/12549574_merged.pdf"
  "US12513139B1|external_capability_access_control|https://api.uspto.gov/api/v1/download/applications/19286205/81b56137-9297-4cbe-80eb-f23570113743/files/12513139_merged.pdf"
  "US20250117593A1|self_guardrail_llm_responses|https://api.uspto.gov/api/v1/download/applications/18395319/53e3e85c-4e43-4e66-bdfc-56d5e93b7b02/files/631d86cc-cff8-4877-a694-5fc45b5ec7be.pdf"
  "US20250190527A1|guardrail_ml_model_automated_software|https://api.uspto.gov/api/v1/download/applications/19056512/b13c86b6-b4ca-4020-964f-86db779ec54b/files/1f9c59e5-f404-4e6d-9458-b3401c5f643f.pdf"
  "US20250298952A1|genai_tool_formal_verification|https://api.uspto.gov/api/v1/download/applications/18731025/386d6171-28f8-4164-a1e1-5958354934bd/files/4cc82e10-65c1-469c-a59d-9d57317e1382.pdf"
)

manifest="$OUT_DIR/manifest.tsv"
printf "patent_id\tlabel\tpdf_path\ttxt_path\tstatus\tnotes\n" > "$manifest"

for rec in "${records[@]}"; do
  IFS='|' read -r patent_id label url <<< "$rec"
  pdf_path="$OUT_DIR/pdf/${patent_id}.pdf"
  txt_raw="$OUT_DIR/txt/${patent_id}.raw.txt"
  txt_clean="$OUT_DIR/txt/${patent_id}.txt"

  status="ok"
  notes=""

  if ! curl -fsSL --retry 2 --connect-timeout 20 --max-time 300 "$url" -o "$pdf_path"; then
    status="download_failed"
    notes="curl failed"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$patent_id" "$label" "$pdf_path" "$txt_clean" "$status" "$notes" >> "$manifest"
    continue
  fi

  if ! pdftotext -layout "$pdf_path" "$txt_raw"; then
    status="extract_failed"
    notes="pdftotext failed"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$patent_id" "$label" "$pdf_path" "$txt_clean" "$status" "$notes" >> "$manifest"
    continue
  fi

  # Cleanup: normalize line endings, remove non-printable control chars, collapse >2 blank lines.
  tr -d '\000' < "$txt_raw" \
    | sed -E $'s/\r$//' \
    | sed -E 's/[^[:print:]\t]//g' \
    | awk 'BEGIN{blank=0} {if ($0 ~ /^[[:space:]]*$/) {blank++; if (blank<=2) print $0} else {blank=0; print $0}}' \
    > "$txt_clean"

  rm -f "$txt_raw"
  printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$patent_id" "$label" "$pdf_path" "$txt_clean" "$status" "$notes" >> "$manifest"
done

echo "Export complete: $OUT_DIR"
echo "Manifest: $manifest"
