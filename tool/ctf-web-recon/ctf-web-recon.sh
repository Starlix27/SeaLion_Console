#!/usr/bin/env bash
# ctf-web-recon — pipeline ricognizione→attacco per web challenge CTF
# Fasi: dirs (ffuf) → params (form HTML + arjun) → scan (nuclei) → xss (dalfox) → sqli (sqlmap) → ssti (probe + sstimap)
#
# Senza fasi esplicite: esegue TUTTE le fasi in sequenza.
# Con una o più fasi come argomenti posizionali: esegue SOLO quelle.
#   ctf-wr -u http://target ssti        → solo SSTI
#   ctf-wr -u http://target xss sqli    → solo XSS e SQLi
set -uo pipefail

URL="" OUT="" COOKIE="" FAST=0 SKIP="" ONLY="" PARAMS="" ASSUME_YES=0 NO_INSTALL=0 MODE="run"
PHASES_ALL="dirs params scan xss sqli ssti"

B=$'\033[1m'; C=$'\033[1;36m'; G=$'\033[1;32m'; Y=$'\033[1;33m'
R=$'\033[0m'; D=$'\033[90m'; RED=$'\033[1;31m'

usage() {
  cat <<EOF
${B}ctf-wr${R} — pipeline ricognizione → attacco per web challenge CTF

${C}USO${R}
  ctf-wr -u URL [fasi...] [opzioni]

${C}FASI${R} (eseguite sempre in quest'ordine)
  ${Y}dirs${R}    ffuf                    directory e file nascosti
  ${Y}params${R}  form HTML + arjun       parametri nascosti sugli endpoint
  ${Y}scan${R}    nuclei                  CVE note e misconfigurazioni
  ${Y}xss${R}     dalfox                  XSS verificato (headless browser)
  ${Y}sqli${R}    sqlmap                  SQL injection
  ${Y}ssti${R}    probe built-in+sstimap  template injection

  ${G}Senza fasi${R}  → le esegue TUTTE in sequenza (pipeline completa)
  ${G}Con fasi${R}    → esegue SOLO quelle indicate:
      ctf-wr -u http://target ${Y}ssti${R}          ← solo SSTI
      ctf-wr -u http://target ${Y}xss sqli${R}      ← solo XSS e SQLi

${C}OPZIONI${R}
  -u, --url URL       target (obbligatorio)
  -p, --param nome    parametro noto da testare (ripetibile, salta la discovery)
  -o, --out DIR       cartella output (default ./ctf-recon-<timestamp>)
  -c, --cookie "k=v"  cookie di sessione, per target dietro login
  --skip fase,fase    escludi fasi dalla pipeline completa
  --fast              timeout ridotti (nuclei 3m, sqli 2m, xss 1m, ssti 90s)
  -y, --yes           installa le dipendenze mancanti senza chiedere
  --no-install        non installare nulla (le fasi senza tool vengono degradate/saltate)
  -h, --help          questo aiuto

${C}DIPENDENZE${R}
  ctf-wr deps               tabella: cosa c'è e cosa manca
  ctf-wr deps --install     installa tutte le dipendenze mancanti
  ${D}Prima di partire, ctf-wr controlla i tool delle fasi richieste:
  se ne manca uno ti dice PERCHÉ quella fase non partirebbe
  (o in cosa sarebbe limitata) e ti chiede se installarlo subito.
  arjun e sstimap sono opzionali: senza arjun params usa form HTML
  e nomi comuni; senza sstimap ssti usa il probe built-in.${R}

${C}ESEMPI${R}
  ctf-wr -u http://target                         scan completo
  ctf-wr -u http://target ssti                    solo SSTI
  ctf-wr -u "http://target/p?name=x" ssti         SSTI su un parametro noto
  ctf-wr -u http://target/search -p q             parametro noto, niente discovery
  ctf-wr -u http://target -c "session=XXX" sqli   SQLi dietro autenticazione
  ctf-wr -u http://target --skip dirs,params      attacchi diretti, niente recon

${C}OUTPUT${R}
  In <outdir>: dirs.json, endpoints.txt, targets.txt, forms.txt, nuclei.txt,
  xss.txt, sqli.txt, ssti.txt, ssti-probe.txt, errors.log e il riepilogo ${B}report.md${R}.

${D}Le fasi di attacco testano: -p, query nell'URL, form HTML della pagina,
parametri da arjun — e se non trovano nulla, i nomi di parametro più comuni.${R}
EOF
  exit "${1:-0}"
}

# ─── Parsing argomenti ────────────────────────────────────────────────────────
is_phase() { case " $PHASES_ALL " in *" $1 "*) return 0;; esac; return 1; }

while [[ $# -gt 0 ]]; do case "$1" in
  -u|--url)    URL="${2:-}"; shift 2;;
  -o|--out)    OUT="${2:-}"; shift 2;;
  -c|--cookie) COOKIE="${2:-}"; shift 2;;
  -p|--param)  PARAMS="$PARAMS ${2:-}"; shift 2;;
  --fast)      FAST=1; shift;;
  --skip)      SKIP="${2:-}"; shift 2;;
  -y|--yes)    ASSUME_YES=1; shift;;
  --no-install) NO_INSTALL=1; shift;;
  -h|--help)   usage 0;;
  deps)        MODE="deps"; shift;;
  --install)   DEPS_INSTALL=1; shift;;
  all)         shift;;
  *)
    # argomento posizionale: deve essere una o più fasi (anche separate da virgola)
    IFS=',' read -ra _toks <<< "$1"
    for _t in "${_toks[@]}"; do
      if is_phase "$_t"; then ONLY="$ONLY $_t"
      else
        echo -e "${RED}Fase sconosciuta: '$_t'${R}" >&2
        echo -e "Fasi valide: ${Y}$PHASES_ALL${R}  (oppure: ctf-wr -h)" >&2
        exit 1
      fi
    done
    shift;;
esac; done

# ─── Dipendenze ───────────────────────────────────────────────────────────────
declare -A TOOL=( [dirs]=ffuf [params]=arjun [scan]=nuclei [xss]=dalfox [sqli]=sqlmap [ssti]=sstimap )
# tool opzionali: senza di loro la fase parte comunque in modalità degradata
declare -A DEGRADED=( [params]="solo form HTML + nomi comuni" [ssti]="solo probe built-in" )

have() { command -v "$1" >/dev/null 2>&1; }

wordlist_dirs() {
  for w in /usr/share/seclists/Discovery/Web-Content/common.txt \
           /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
           /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt; do
    [[ -f "$w" ]] && { echo "$w"; return 0; }
  done
  return 1
}

USER_BIN="$HOME/.local/bin"

install_tool() {
  local t="$1"
  echo -e "${C}[*] Installazione di $t…${R}"
  case "$t" in
    ffuf|nuclei|sqlmap|seclists)
      sudo apt-get install -y "$t" ;;
    arjun)
      python3 -m pip install --user arjun 2>/dev/null \
        || python3 -m pip install --user --break-system-packages arjun ;;
    dalfox)
      local tmp url bin
      tmp=$(mktemp -d)
      url=$(python3 - <<'PY'
import json, urllib.request
with urllib.request.urlopen("https://api.github.com/repos/hahwul/dalfox/releases/latest", timeout=30) as r:
    rel = json.load(r)
for a in rel["assets"]:
    if "linux-x86_64" in a["name"] and a["name"].endswith(".tar.gz"):
        print(a["browser_download_url"]); break
PY
)
      [[ -n "$url" ]] || { echo "URL release dalfox non trovato"; return 1; }
      curl -fsSL "$url" -o "$tmp/dalfox.tar.gz" \
        && tar -xzf "$tmp/dalfox.tar.gz" -C "$tmp" \
        && bin=$(find "$tmp" -name dalfox -type f | head -1) \
        && mkdir -p "$USER_BIN" \
        && install -m755 "$bin" "$USER_BIN/dalfox" \
        && rm -rf "$tmp" ;;
    sstimap)
      local dest="$HOME/.sealionconsole/tools/ctf-web-toolkit/SSTImap"
      [[ -d "$dest" ]] || git clone --depth 1 https://github.com/vladko312/SSTImap.git "$dest" || return 1
      python3 -m pip install --user -r "$dest/requirements.txt" 2>/dev/null \
        || python3 -m pip install --user --break-system-packages -r "$dest/requirements.txt" || return 1
      mkdir -p "$USER_BIN"
      printf '#!/usr/bin/env bash\nexec python3 "%s/sstimap.py" "$@"\n' "$dest" > "$USER_BIN/sstimap"
      chmod +x "$USER_BIN/sstimap" ;;
    *)
      echo "Non so installare '$t'"; return 1 ;;
  esac
}

SKIP_N=" ${SKIP//,/ } "
skipped() { case "$SKIP_N" in *" $1 "*) return 0;; esac; return 1; }
RUN_LIST="${ONLY:- $PHASES_ALL}"
RUN_LIST=" ${RUN_LIST# }"   # normalizza: spazio iniziale per il matching
active()  { skipped "$1" && return 1; case "$RUN_LIST" in *" $1"*|*" $1 "*) return 0;; *) return 1;; esac; }

# Tabella stato fasi+tool, raccolta mancanti in MISSING_TOOLS; poi offre installazione.
MISSING_TOOLS=()
ensure_deps() {
  echo -e "${C}═══ Fasi e dipendenze ═══${R}"
  local -a missing=()
  local p t
  for p in $RUN_LIST; do
    t="${TOOL[$p]}"
    if skipped "$p"; then
      printf "  ${D}%-7s saltata (--skip)${R}\n" "$p"
    elif have "$t"; then
      printf "  ${G}✓ %-7s${R} ${D}(%s)${R}\n" "$p" "$t"
    elif [[ -n "${DEGRADED[$p]:-}" ]]; then
      printf "  ${Y}⚠ %-7s (%s mancante → %s)${R}\n" "$p" "$t" "${DEGRADED[$p]}"
      missing+=("$t")
    else
      printf "  ${RED}✗ %-7s (%s) — MANCANTE: senza %s questa fase non parte${R}\n" "$p" "$t" "$t"
      missing+=("$t")
    fi
  done
  # la fase dirs vuole anche una wordlist
  if active dirs && ! wordlist_dirs >/dev/null; then
    printf "  ${RED}✗ %-7s (seclists) — MANCANTE: niente wordlist per il fuzzing${R}\n" "dirs"
    missing+=("seclists")
  fi

  ((${#missing[@]} == 0)) && return 0

  # dedup
  local -a uniq=(); local m
  for m in "${missing[@]}"; do [[ " ${uniq[*]} " == *" $m "* ]] || uniq+=("$m"); done

  if [[ $NO_INSTALL -eq 1 ]]; then
    echo -e "${Y}Proseguo con i tool disponibili (--no-install).${R}"
    echo -e "${D}Per installare i mancanti: ctf-wr deps --install${R}"
    MISSING_TOOLS=("${uniq[@]}"); return 1
  fi

  local ans=""
  if [[ $ASSUME_YES -eq 1 ]]; then ans="s"
  elif [[ -t 0 ]]; then
    read -rp "$(echo -e "${Y}Installo ora i tool mancanti (${uniq[*]})? [S/n]${R} ")" ans
  elif { exec 9</dev/tty; } 2>/dev/null; then
    read -rp "$(echo -e "${Y}Installo ora i tool mancanti (${uniq[*]})? [S/n]${R} ")" ans <&9 || ans="n"
    exec 9<&-
  else
    echo -e "${Y}Tool mancanti: ${uniq[*]}${R} — rilancia con ${B}-y${R} per installarli automaticamente."
    MISSING_TOOLS=("${uniq[@]}"); return 1
  fi
  [[ -z "$ans" || "$ans" =~ ^[sSyY]$ ]] || {
    echo -e "${D}Ok, proseguo con i tool disponibili. Per installare dopo: ctf-wr deps --install${R}"
    MISSING_TOOLS=("${uniq[@]}"); return 1
  }

  local fail=()
  for m in "${uniq[@]}"; do
    if install_tool "$m"; then
      { have "$m" || [[ "$m" == seclists ]]; } \
        && echo -e "  ${G}✓ $m installato${R}" \
        || { echo -e "  ${RED}✗ $m: installato ma non trovato (controlla che ~/.local/bin sia nel PATH)${R}"; fail+=("$m"); }
    else
      echo -e "  ${RED}✗ $m: installazione fallita${R}"; fail+=("$m")
    fi
  done
  hash -r
  MISSING_TOOLS=("${fail[@]}")
  [[ ${#fail[@]} -eq 0 ]]
}

# ─── Modalità "deps": tabella dipendenze ─────────────────────────────────────
if [[ "$MODE" == "deps" ]]; then
  echo -e "${B}Dipendenze di ctf-wr${R}\n"
  printf "  %-8s %-10s %s\n" "FASE" "TOOL" "STATO"
  missing_any=()
  for p in $PHASES_ALL; do
    t="${TOOL[$p]}"
    if have "$t"; then printf "  %-8s %-10s ${G}✓ %s${R}\n" "$p" "$t" "$(command -v "$t")"
    elif [[ -n "${DEGRADED[$p]:-}" ]]; then
      printf "  %-8s %-10s ${Y}⚠ mancante (opzionale: %s)${R}\n" "$p" "$t" "${DEGRADED[$p]}"; missing_any+=("$t")
    else printf "  %-8s %-10s ${RED}✗ mancante${R}\n" "$p" "$t"; missing_any+=("$t"); fi
  done
  if w=$(wordlist_dirs); then printf "  %-8s %-10s ${G}✓ %s${R}\n" "dirs" "wordlist" "$w"
  else printf "  %-8s %-10s ${RED}✗ mancante (apt: seclists)${R}\n" "dirs" "wordlist"; missing_any+=("seclists"); fi
  echo
  if [[ "${DEPS_INSTALL:-0}" == "1" ]]; then
    if ((${#missing_any[@]} == 0)); then echo -e "${G}Tutto installato, niente da fare.${R}"; exit 0; fi
    for m in "${missing_any[@]}"; do install_tool "$m" || echo -e "${RED}✗ $m: fallita${R}"; done
    hash -r
    echo -e "\n${G}Fatto. Ricontrolla con: ctf-wr deps${R}"
  elif ((${#missing_any[@]})); then
    echo -e "Per installare i mancanti: ${B}ctf-wr deps --install${R}"
  else
    echo -e "${G}Tutto installato.${R}"
  fi
  exit 0
fi

[[ -z "$URL" ]] && usage 0
URL="${URL%/}"

TS=$(date +%Y%m%d-%H%M%S)
OUT="${OUT:-./ctf-recon-$TS}"
mkdir -p "$OUT"
REPORT="$OUT/report.md"
GET_T="$OUT/targets.txt"       # URL GET con parametri, uno per riga
POST_T="$OUT/post-targets.txt" # "url<TAB>data" per form POST
ERRLOG="$OUT/errors.log"       # stderr dei tool (niente fallimenti silenziosi)
BUILT=0

hdr()     { echo -e "\n${C}═══ [$1] $2 ═══${R}"; echo -e "\n## [$1] $2\n" >> "$REPORT"; }
note()    { echo -e "${D}$1${R}"; echo "$1" >> "$REPORT"; }
find_()   { echo -e "${Y}[+]${R} $1"; echo "- ⚠️ $1" >> "$REPORT"; }
warn_err() { [[ -s "$ERRLOG" ]] && note "alcuni tool hanno riportato errori — dettagli in $ERRLOG"; }

T_XSS=180; T_SQLI=300; T_SSTI=240; T_NUCLEI=600; T_ARJUN=300
[[ $FAST -eq 1 ]] && { T_XSS=60; T_SQLI=120; T_SSTI=90; T_NUCLEI=180; T_ARJUN=120; }

FFUF_H=(); ARJUN_H=""; SQLI_C=(); DALFOX_H=(); SSTI_C=(); NUCLEI_H=()
if [[ -n "$COOKIE" ]]; then
  FFUF_H=(-H "Cookie: $COOKIE"); ARJUN_H="Cookie: $COOKIE"
  SQLI_C=(--cookie "$COOKIE"); DALFOX_H=(-H "Cookie: $COOKIE")
  SSTI_C=(-c "$COOKIE"); NUCLEI_H=(-H "Cookie: $COOKIE")
fi

echo "# ctf-web-recon — $URL" > "$REPORT"
echo "- Data: $(date)" >> "$REPORT"
echo -e "${G}[ctf-wr]${R} target: $URL  →  out: $OUT"

ensure_deps

# ─── Raccolta target con parametri ──────────────────────────────────────────
# Sorgenti: -p, query nell'URL, form HTML (built-in), arjun (solo modalità full),
# fallback su parametri comuni. Chiamata dalla fase params (full) o dalle fasi
# di attacco (quick, se params non è stata eseguita).
build_targets() {
  local mode="$1"
  [[ $BUILT -eq 1 ]] && return 0
  BUILT=1
  : > "$GET_T"; : > "$POST_T"

  [[ "$URL" == *\?* ]] && echo "$URL" >> "$GET_T"
  for p in $PARAMS; do echo "$URL?$p=1" >> "$GET_T"; done

  # Form HTML della pagina principale (GET e POST)
  python3 - "$URL" "$COOKIE" > "$OUT/forms.txt" 2>>"$ERRLOG" << 'PY'
import sys, urllib.request, urllib.parse, html.parser

url, cookie = sys.argv[1], sys.argv[2]
headers = {"User-Agent": "ctf-wr"}
if cookie:
    headers["Cookie"] = cookie
try:
    body = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15).read().decode("utf-8", "replace")
except Exception:
    sys.exit(0)

class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.cur = [], None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
        elif tag in ("input", "textarea", "select") and self.cur is not None:
            n = a.get("name")
            if n and a.get("type", "text").lower() not in ("submit", "button", "image", "reset"):
                self.cur["inputs"].append(n)
    def handle_endtag(self, tag):
        if tag == "form" and self.cur is not None:
            self.forms.append(self.cur); self.cur = None

p = Forms(); p.feed(body)
for f in p.forms:
    if not f["inputs"]:
        continue
    action = urllib.parse.urljoin(url, f["action"])
    data = "&".join(f"{i}=1" for i in dict.fromkeys(f["inputs"]))
    if f["method"] == "post":
        print(f"POST\t{action}\t{data}")
    else:
        print(f"GET\t{action}?{data}")
PY
  local nf=0
  while IFS=$'\t' read -r m a b; do
    case "$m" in
      GET)  echo "$a" >> "$GET_T"; nf=$((nf+1));;
      POST) printf '%s\t%s\n' "$a" "$b" >> "$POST_T"; nf=$((nf+1));;
    esac
  done < "$OUT/forms.txt"
  [[ $nf -gt 0 ]] && note "form HTML: $nf target (vedi forms.txt)"

  # arjun solo in modalità full (fase params esplicita): lento
  if [[ "$mode" == full ]]; then
    if ! have arjun; then
      note "arjun mancante — discovery limitata ai form HTML"
    else
      local ENDPOINTS=("$URL")
      [[ -f "$OUT/endpoints.txt" ]] && while IFS=$'\t' read -r st u; do
        [[ "$st" == "200" ]] && ENDPOINTS+=("$u")
      done < <(head -5 "$OUT/endpoints.txt")
      for ep in "${ENDPOINTS[@]}"; do
        note "arjun su: $ep"
        # N.B. niente --stable: aggiunge 3-9s di sleep a OGNI richiesta
        local ARJ_ARGS=(-u "$ep" -c 500 -oJ "$OUT/params.json")
        [[ -n "$ARJUN_H" ]] && ARJ_ARGS+=(--headers "$ARJUN_H")
        timeout "$T_ARJUN" arjun "${ARJ_ARGS[@]}" 2>>"$ERRLOG"
        python3 - "$OUT/params.json" >> "$GET_T" << 'PY'
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
    fi
  fi

  sort -uo "$GET_T" "$GET_T"
  [[ -s "$POST_T" ]] && sort -uo "$POST_T" "$POST_T"

  # Fallback: niente parametri scoperti → lista di nomi comuni
  if [[ ! -s "$GET_T" && ! -s "$POST_T" ]]; then
    note "nessun parametro scoperto — provo i nomi di parametro più comuni"
    for p in name q query search input text message comment content data value \
             user username id page template lang file path url redirect next; do
      echo "$URL?$p=1" >> "$GET_T"
    done
  fi

  note "target GET: $(grep -c . "$GET_T" 2>/dev/null || true) — target POST: $(grep -c . "$POST_T" 2>/dev/null || true)"
}

# ─── Fase dirs: ffuf ────────────────────────────────────────────────────────
if active dirs; then
  if ! have ffuf; then note "dirs: saltata (ffuf mancante)";
  elif ! WL=$(wordlist_dirs); then note "dirs: saltata (nessuna wordlist — installa: sudo apt install seclists)";
  else
    hdr dirs "Directory discovery (ffuf)"
    ffuf -u "$URL/FUZZ" -w "$WL" -mc 200,204,301,302,307,401,403 "${FFUF_H[@]}" \
         -of json -o "$OUT/dirs.json" -s -t 40 -ac 2>>"$ERRLOG"
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
    sort -u "$OUT/endpoints.txt" 2>/dev/null | column -t -s$'\t' 2>/dev/null | head -30
    note '```'; cat "$OUT/endpoints.txt" 2>/dev/null >> "$REPORT"; note '```'
  fi
fi

# ─── Fase params: form HTML + arjun ─────────────────────────────────────────
if active params; then
  hdr params "Parameter discovery (form HTML + arjun)"
  build_targets full
  if [[ -s "$GET_T" ]]; then
    cat "$GET_T"
    note "target con parametri:"; sed 's/^/- /' "$GET_T" >> "$REPORT"
  fi
  [[ -s "$POST_T" ]] && { cut -f1,2 "$POST_T"; note "form POST:"; sed 's/^/- /' "$POST_T" >> "$REPORT"; }
  warn_err
fi

# ─── Fase scan: nuclei ──────────────────────────────────────────────────────
if active scan; then
  if ! have nuclei; then note "scan: saltata (nuclei mancante)";
  else
    hdr scan "Vulnerability scan (nuclei)"
    timeout "$T_NUCLEI" nuclei -u "$URL" -severity critical,high,medium "${NUCLEI_H[@]}" \
        -silent -nc -o "$OUT/nuclei.txt" 2>>"$ERRLOG"
    if [[ -s "$OUT/nuclei.txt" ]]; then cat "$OUT/nuclei.txt"; sed 's/^/- /' "$OUT/nuclei.txt" >> "$REPORT"
    else note "nessun finding"; fi
    warn_err
  fi
fi

# ─── Fase xss: dalfox ───────────────────────────────────────────────────────
if active xss; then
  if ! have dalfox; then note "xss: saltata (dalfox mancante)";
  else
    hdr xss "XSS scan (dalfox)"
    build_targets quick
    while read -r t; do
      [[ -z "$t" ]] && continue
      note "test: $t"
      timeout "$T_XSS" dalfox url "$t" "${DALFOX_H[@]}" --silence --no-color 2>>"$ERRLOG" \
        | tee -a "$OUT/xss.txt" | grep -Ei "\[POC\]|\[V\]" | head -5
    done < "$GET_T"
    while IFS=$'\t' read -r u d; do
      [[ -z "$u" ]] && continue
      note "test (POST): $u"
      timeout "$T_XSS" dalfox url "$u" -X POST -d "$d" "${DALFOX_H[@]}" --silence --no-color 2>>"$ERRLOG" \
        | tee -a "$OUT/xss.txt" | grep -Ei "\[POC\]|\[V\]" | head -5
    done < "$POST_T"
    if grep -qEi "\[POC\]|\[V\]" "$OUT/xss.txt" 2>/dev/null; then
      find_ "XSS trovato! vedi $OUT/xss.txt"
      grep -Ei "\[POC\]" "$OUT/xss.txt" | sed 's/^/  - /' >> "$REPORT"
    else note "nessun XSS confermato"; fi
    warn_err
  fi
fi

# ─── Fase sqli: sqlmap ──────────────────────────────────────────────────────
if active sqli; then
  if ! have sqlmap; then note "sqli: saltata (sqlmap mancante)";
  else
    hdr sqli "SQLi scan (sqlmap)"
    build_targets quick
    while read -r t; do
      [[ -z "$t" ]] && continue
      note "test: $t"
      timeout "$T_SQLI" sqlmap -u "$t" "${SQLI_C[@]}" --batch --level 1 --risk 1 \
        --output-dir="$OUT/sqlmap" 2>>"$ERRLOG" | tee -a "$OUT/sqli.txt" | grep -i "is vulnerable" | head -3
    done < "$GET_T"
    while IFS=$'\t' read -r u d; do
      [[ -z "$u" ]] && continue
      note "test (POST): $u"
      timeout "$T_SQLI" sqlmap -u "$u" --data "$d" "${SQLI_C[@]}" --batch --level 1 --risk 1 \
        --output-dir="$OUT/sqlmap" 2>>"$ERRLOG" | tee -a "$OUT/sqli.txt" | grep -i "is vulnerable" | head -3
    done < "$POST_T"
    if grep -qi "is vulnerable" "$OUT/sqli.txt" 2>/dev/null; then
      find_ "SQLi trovata! vedi $OUT/sqli.txt — approfondisci con: sqlmap -u TARGET --dbs"
    else note "nessuna SQLi confermata"; fi
    warn_err
  fi
fi

# ─── Fase ssti: probe built-in + sstimap ────────────────────────────────────
if active ssti; then
  hdr ssti "SSTI (probe built-in + sstimap)"
  build_targets quick

  # Probe built-in: funziona anche senza sstimap. Inietta marker aritmetici
  # in ogni parametro (GET e POST) e cerca il risultato valutato nel response.
  python3 - "$COOKIE" "$GET_T" "$POST_T" "$OUT/ssti-probe.txt" 2>>"$ERRLOG" << 'PY'
import sys, urllib.request, urllib.parse

cookie, get_f, post_f, out_f = sys.argv[1:5]
PAYLOADS = ["{{7*7}}", "${7*7}}", "#{7*7}", "*{7*7}"]
HEADERS = {"User-Agent": "ctf-wr"}
if cookie:
    HEADERS["Cookie"] = cookie

def fetch(u, data=None):
    try:
        req = urllib.request.Request(u, data=data.encode() if data else None, headers=HEADERS)
        return urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
    except Exception:
        return ""

def test(url, pairs, is_post, hits):
    baseline = fetch(url, urllib.parse.urlencode(pairs) if is_post else None)
    for i, (name, _) in enumerate(pairs):
        for pl in PAYLOADS:
            inj = [(n, pl if j == i else v) for j, (n, v) in enumerate(pairs)]
            qs = urllib.parse.urlencode(inj)
            body = fetch(url, qs) if is_post else fetch(url + ("&" if "?" in url else "?") + qs)
            if "49" in body and "49" not in baseline and pl not in body:
                hits.append(("POST" if is_post else "GET", url, name, pl))
                break

hits = []
for line in open(get_f):
    u = line.strip()
    if "?" not in u:
        continue
    base, q = u.split("?", 1)
    pairs = urllib.parse.parse_qsl(q)
    if pairs:
        test(base, pairs, False, hits)
for line in open(post_f):
    parts = line.rstrip("\n").split("\t")
    if len(parts) != 2:
        continue
    pairs = urllib.parse.parse_qsl(parts[1])
    if pairs:
        test(parts[0], pairs, True, hits)

with open(out_f, "w") as f:
    for method, u, name, pl in hits:
        f.write(f"[{method}] {u} — parametro '{name}' valutato con {pl}\n")
print(f"probe: {len(hits)} parametro/i valutano template" if hits else "probe: nessuna valutazione rilevata")
PY

  if [[ -s "$OUT/ssti-probe.txt" ]]; then
    while read -r h; do find_ "SSTI: $h"; done < "$OUT/ssti-probe.txt"
    note "conferma/exploit con sstimap sui parametri sopra"
  fi

  if ! have sstimap; then
    note "sstimap mancante — ctf-wr deps --install per identificare il motore e sfruttare"
  else
    while read -r t; do
      [[ -z "$t" ]] && continue
      note "sstimap: $t"
      timeout "$T_SSTI" sstimap -u "$t" "${SSTI_C[@]}" 2>>"$ERRLOG" \
        | tee -a "$OUT/ssti.txt" | grep -Ei "is injectable|injection point|Engine:" | head -3
    done < "$GET_T"
    while IFS=$'\t' read -r u d; do
      [[ -z "$u" ]] && continue
      note "sstimap (POST): $u"
      timeout "$T_SSTI" sstimap -u "$u" --data "$d" "${SSTI_C[@]}" 2>>"$ERRLOG" \
        | tee -a "$OUT/ssti.txt" | grep -Ei "is injectable|injection point|Engine:" | head -3
    done < "$POST_T"
    if grep -qiE "is injectable|injection point" "$OUT/ssti.txt" 2>/dev/null; then
      find_ "SSTI confermata da sstimap! vedi $OUT/ssti.txt — exploit: sstimap -u TARGET --os-shell"
    elif [[ ! -s "$OUT/ssti-probe.txt" ]]; then
      note "nessuna SSTI confermata"
    fi
  fi
  warn_err
fi

# ─── Riepilogo ──────────────────────────────────────────────────────────────
echo -e "\n${C}═══ RIEPILOGO ═══${R}"
s=0
if [[ -s "$OUT/nuclei.txt" ]]; then echo "  scan:  $(grep -c . "$OUT/nuclei.txt") finding → nuclei.txt"; s=1; fi
if grep -qEi "\[POC\]|\[V\]" "$OUT/xss.txt" 2>/dev/null; then echo "  xss:   POC trovati → xss.txt"; s=1; fi
if grep -qi "is vulnerable" "$OUT/sqli.txt" 2>/dev/null; then echo "  sqli:  parametro vulnerabile → sqli.txt"; s=1; fi
if [[ -s "$OUT/ssti-probe.txt" ]]; then echo "  ssti:  $(grep -c . "$OUT/ssti-probe.txt") parametro/i valutano template → ssti-probe.txt"; s=1; fi
if grep -qiE "is injectable|injection point" "$OUT/ssti.txt" 2>/dev/null; then echo "  ssti:  confermata da sstimap → ssti.txt"; s=1; fi
[[ $s -eq 0 ]] && echo "  nessun finding confermato"
echo -e "  report: ${B}$REPORT${R}"
note ""
note "---"
note "I finding vanno verificati a mano: i tool danno candidati, non flag."
