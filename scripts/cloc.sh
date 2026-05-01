#!/bin/bash
# OpenScanProxy - Code line count by language

EXCL=(-not -path "*/node_modules/*" -not -path "*/build/*" -not -path "*/web/dist/*"
      -not -path "*/.claude/*" -not -path "*/.git/*" -not -path "*/logs/*"
      -not -name "*portal_*")

count() {
  local files n
  files=$(find . "${EXCL[@]}" "$@" 2>/dev/null || true)
  n=$(echo "$files" | xargs cat 2>/dev/null | wc -l 2>/dev/null || echo 0)
  echo "${n// /}"
}

declare -A labels=(
  [cpp]="C++ Source"  [hpp]="C++ Header"
  [vue]="Vue"         [js]="JavaScript"
  [css]="CSS"         [sh]="Shell"
  [json]="JSON"       [md]="Markdown"
)

echo "=== OpenScanProxy Code Statistics ==="
echo ""
printf "  %-16s %s\n" "Language" "Lines"
printf "  %-16s %s\n" "--------" "-----"

total=0

for ext in cpp hpp vue js css sh; do
  n=$(count -name "*.$ext")
  printf "  %-16s %6s\n" "${labels[$ext]}" "$n"
  total=$((total + n))
done

n=$(count -name "Dockerfile")
printf "  %-16s %6s\n" "Dockerfile" "$n"
total=$((total + n))

n=$(count \( -name "*.yml" -o -name "*.yaml" \))
printf "  %-16s %6s\n" "YAML" "$n"
total=$((total + n))

n=$(count -name "*.json")
printf "  %-16s %6s\n" "JSON" "$n"
total=$((total + n))

n=$(count -name "*.md")
printf "  %-16s %6s\n" "Markdown" "$n"
total=$((total + n))

echo "  ------------------------------"
printf "  %-16s %6s\n" "Total" "$total"
