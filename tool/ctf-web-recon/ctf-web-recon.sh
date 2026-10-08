#!/usr/bin/env bash
# ctf-web-recon — pipeline ricognizione→attacco per web challenge CTF
# Fasi: ffuf (dirs) → arjun (params) → nuclei (scan) → dalfox (XSS) → sqlmap (SQLi) → sstimap (SSTI)
set -uo pipefail

URL="" OUT="" COOKIE="" FAST=0 SKIP=""
usage() {
  echo "Uso: ctf-wr -u URL [-o outdir] [-c \"cookie\"] [--skip fase,fase] [--fast]"
  echo "Fasi: dirs params scan xss sqli ssti"
  exit 1
}
while [[ $# -gt 0 ]]; do case "$1" in
  -u|--url)  URL="$2"; shift 2;;
  -o|--out)  OUT="$2"; shift 2;;
  -c|--cookie) COOKIE="$2"; shift 2;;
  --fast)    FAST=1; shift;;
  --skip)    SKIP="$2"; shift 2;;
  -h|--help) usage;;
  *) echo "opzione sconosciuta: $1"; usage;;
esac; done
[[ -z "$URL" ]] && usage
URL="${URL%/}"

TS=$(date +%Y%m%d-%H%M%S)
OUT="${OUT:-./ctf-recon-$TS}"
mkdir -p "$OUT"
REPORT="$OUT/report.md"
TARGETS="$OUT/targets.txt"; : > "$TARGETS"

have()    { command -v "$1" >/dev/null 2>&1; }
skipped() { case ",$SKIP," in *",$1,"*) return 0;; *) return 1;; esac; }
hdr()     { echo -e "\n\033[1;36m═══ [$1] $2 ═══\033[0m"; echo -e "\n## [$1] $2\n" >> "$REPORT"; }
note()    { echo -e "\033[90m$1\033[0m"; echo "$1" >> "$REPORT"; }
find_()   { echo -e "\033[1;33m[+]\033[0m $1"; echo "- ⚠️ $1" >> "$REPORT"; }

T_XSS=180; T_SQLI=300; T_SSTI=180; T_NUCLEI=600
[[ $FAST -eq 1 ]] && { T_XSS=60; T_SQLI=120; T_SSTI=60; T_NUCLEI=180; }

CURL_OPTS=(-sk --max-time 15)
FFUF_H=(); ARJUN_H=""; SQLI_C=(); DALFOX_H=(); SSTI_C=(); NUCLEI_H=()
if [[ -n "$COOKIE" ]]; then
  FFUF_H=(-H "Cookie: $COOKIE"); ARJUN_H="Cookie: $COOKIE"
  SQLI_C=(--cookie "$COOKIE"); DALFOX_H=(-H "Cookie: $COOKIE")
  SSTI_C=(-c "$COOKIE"); NUCLEI_H=(-H "Cookie: $COOKIE")
fi

echo "# ctf-web-recon — $URL" > "$REPORT"
echo "- Data: $(date)" >> "$REPORT"
echo -e "\033[1;32m[ctf-web-recon]\033[0m target: $URL  →  out: $OUT"

# ─── Fase 1: ffuf — directory/file discovery ────────────────────────────────
if skipped dirs; then note "dirs: saltata"; elif ! have ffuf; then note "dirs: ffuf mancante (install ctf-web-toolkit)";
else
  hdr 1 "Directory discovery (ffuf)"
  WL=/usr/share/seclists/Discovery/Web-Content/common.txt
  [[ -f "$WL" ]] || WL=/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
  ffuf -u "$URL/FUZZ" -w "$WL" -mc 200,204,301,302,307,401,403 "${FFUF_H[@]}" \
       -of json -o "$OUT/dirs.json" -s -t 40 -ac 2>/dev/null
  python3 - "$OUT/dirs.json" "$OUT/endpoints.txt" << 'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    with open(sys.argv[2], "w") as f:
        for r in d.get("results", []):
            f.write(f"{r['status']}\t{r['url']}\n")
    print(f"{len(d.get('results', []))} endpoint trovati")
except Exception as e:
    print(f"parse fallito: {e}")
PY
  sort -u "$OUT/endpoints.txt" 2>/dev/null | column -t -s$'\t' | head -30
  note "\`\`\`"; cat "$OUT/endpoints.txt" 2>/dev/null >> "$REPORT"; note "\`\`\`"
fi

# ─── Fase 2: arjun — parametri nascosti ─────────────────────────────────────
ENDPOINTS=("$URL")
[[ -f "$OUT/endpoints.txt" ]] && while IFS=$'\t' read -r st u; do
  [[ "$st" == "200" ]] && ENDPOINTS+=("$u")
done < <(head -5 "$OUT/endpoints.txt")

if skipped params; then note "params: saltata"; elif ! have arjun; then note "params: arjun mancante";
else
  hdr 2 "Parameter discovery (arjun)"
  for ep in "${ENDPOINTS[@]}"; do
    note "analisi: $ep"
    ARJ_ARGS=(-u "$ep" --stable -oJ "$OUT/params.json")
    [[ -n "$ARJUN_H" ]] && ARJ_ARGS+=(--headers "$ARJUN_H")
    timeout 120 arjun "${ARJ_ARGS[@]}" 2>/dev/null
    python3 - "$OUT/params.json" "$ep" >> "$TARGETS" << 'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    for u, params in d.items():
        ps = params.get("params", params) if isinstance(params, dict) else params
        if ps:
            print(u.split("?")[0] + "?" + "&".join(f"{p}=1" for p in ps))
except Exception:
    pass
PY
  done
  sort -uo "$TARGETS" "$TARGETS"
  if [[ -s "$TARGETS" ]]; then
    cat "$TARGETS"
    note "target con parametri:"; sed 's/^/- /' "$TARGETS" >> "$REPORT"
  else
    note "nessun parametro trovato — le fasi di attacco useranno l'URL base"
  fi
fi
[[ -s "$TARGETS" ]] || echo "$URL" >> "$TARGETS"

# ─── Fase 3: nuclei — scan CVE/misconfig ────────────────────────────────────
if skipped scan; then note "scan: saltata"; elif ! have nuclei; then note "scan: nuclei mancante";
else
  hdr 3 "Vulnerability scan (nuclei)"
  timeout "$T_NUCLEI" nuclei -u "$URL" -severity critical,high,medium "${NUCLEI_H[@]}" \
      -silent -nc -o "$OUT/nuclei.txt" 2>/dev/null
  if [[ -s "$OUT/nuclei.txt" ]]; then cat "$OUT/nuclei.txt"; sed 's/^/- /' "$OUT/nuclei.txt" >> "$REPORT"
  else note "nessun finding"; fi
fi

# ─── Fase 4: dalfox — XSS ───────────────────────────────────────────────────
if skipped xss; then note "xss: saltata"; elif ! have dalfox; then note "xss: dalfox mancante (install ctf-web-toolkit)";
else
  hdr 4 "XSS scan (dalfox)"
  while read -r t; do
    note "test: $t"
    timeout "$T_XSS" dalfox url "$t" "${DALFOX_H[@]}" --silence --no-color --no-spinner 2>/dev/null \
      | tee -a "$OUT/xss.txt" | grep -Ei "\[POC\]|\[V\]" | head -5
  done < "$TARGETS"
  if grep -qEi "\[POC\]|\[V\]" "$OUT/xss.txt" 2>/dev/null; then
    find_ "XSS trovato! vedi $OUT/xss.txt"
    grep -Ei "\[POC\]" "$OUT/xss.txt" | sed 's/^/  - /' >> "$REPORT"
  else note "nessun XSS confermato"; fi
fi

# ─── Fase 5: sqlmap — SQLi ──────────────────────────────────────────────────
if skipped sqli; then note "sqli: saltata"; elif ! have sqlmap; then note "sqli: sqlmap mancante";
else
  hdr 5 "SQLi scan (sqlmap)"
  while read -r t; do
    note "test: $t"
    timeout "$T_SQLI" sqlmap -u "$t" "${SQLI_C[@]}" --batch --level 1 --risk 1 \
      --output-dir="$OUT/sqlmap" 2>/dev/null | tee -a "$OUT/sqli.txt" | grep -i "is vulnerable" | head -3
  done < "$TARGETS"
  if grep -qi "is vulnerable" "$OUT/sqli.txt" 2>/dev/null; then
    find_ "SQLi trovata! vedi $OUT/sqli.txt — approfondisci con: sqlmap -u TARGET --dbs"
  else note "nessuna SQLi confermata"; fi
fi

# ─── Fase 6: sstimap — SSTI ─────────────────────────────────────────────────
if skipped ssti; then note "ssti: saltata"; elif ! have sstimap; then note "ssti: sstimap mancante (install ctf-web-toolkit)";
else
  hdr 6 "SSTI scan (sstimap)"
  while read -r t; do
    note "test: $t"
    timeout "$T_SSTI" sstimap -u "$t" "${SSTI_C[@]}" 2>/dev/null \
      | tee -a "$OUT/ssti.txt" | grep -Ei "injectable|engine" | head -3
  done < "$TARGETS"
  if grep -qiE "is injectable|injection point" "$OUT/ssti.txt" 2>/dev/null; then
    find_ "SSTI trovata! vedi $OUT/ssti.txt — approfondisci con: sstimap -u TARGET --os-shell"
  else note "nessuna SSTI confermata"; fi
fi

echo -e "\n\033[1;32m[ctf-web-recon]\033[0m completato → report: $REPORT"
note ""
note "---"
note "Ricorda: l'automazione mappa il terreno. Le CTF si vincono leggendo il codice (JS, sorgenti leakati, logica custom)."
