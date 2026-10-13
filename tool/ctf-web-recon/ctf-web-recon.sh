#!/usr/bin/env bash
# ctf-web-recon — pipeline ricognizione→attacco per web challenge CTF
# Fasi: dirs (ffuf) → params (form HTML + arjun) → scan (nuclei) → xss (dalfox) → sqli (sqlmap) → ssti (probe + sstimap)
set -uo pipefail

URL="" OUT="" COOKIE="" FAST=0 SKIP="" ONLY="" PARAMS=""

usage() {
  cat <<'EOF'
ctf-wr — ricognizione + attacco per web challenge CTF

Uso: ctf-wr -u URL [fasi...] [opzioni]

Fasi (se omesse: tutte):
  dirs     directory e file nascosti      (ffuf)
  params   parametri nascosti             (form HTML + arjun)
  scan     CVE e misconfigurazioni        (nuclei)
  xss      cross-site scripting           (dalfox)
  sqli     SQL injection                  (sqlmap)
  ssti     template injection             (probe built-in + sstimap)

Opzioni:
  -c "k=v"    cookie di sessione
  -p nome     parametro noto da testare (ripetibile)
  -o dir      cartella di output
  --fast      timeout ridotti
  --skip x,y  salta fasi
  -h          questo aiuto

Esempi:
  ctf-wr -u http://target                 scan completo
  ctf-wr -u http://target ssti            solo SSTI
  ctf-wr -u http://target xss sqli        solo XSS e SQLi
  ctf-wr -u http://target/search -p q     parametro noto, senza discovery

Tool mancanti?  install ctf-web-toolkit  li installa tutti (ffuf, arjun,
nuclei, dalfox, sqlmap, sstimap). Quelli assenti vengono segnalati all'avvio.
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do case "$1" in
  -u|--url)    URL="${2:-}"; shift 2;;
  -o|--out)    OUT="${2:-}"; shift 2;;
  -c|--cookie) COOKIE="${2:-}"; shift 2;;
  -p|--param)  PARAMS="$PARAMS ${2:-}"; shift 2;;
  --fast)      FAST=1; shift;;
  --skip)      SKIP="${2:-}"; shift 2;;
  -h|--help)   usage 0;;
  dirs|params|scan|xss|sqli|ssti) ONLY="$ONLY $1"; shift;;
  *) echo "argomento sconosciuto: $1" >&2; usage 1;;
esac; done
[[ -z "$URL" ]] && usage 1
URL="${URL%/}"

TS=$(date +%Y%m%d-%H%M%S)
OUT="${OUT:-./ctf-recon-$TS}"
mkdir -p "$OUT"
REPORT="$OUT/report.md"
GET_T="$OUT/targets.txt"       # URL GET con parametri, uno per riga
POST_T="$OUT/post-targets.txt" # "url<TAB>data" per form POST
BUILT=0

have()    { command -v "$1" >/dev/null 2>&1; }
skipped() { case ",$SKIP," in *",$1,"*) return 0;; *) return 1;; esac; }
RUN_LIST="${ONLY:- dirs params scan xss sqli ssti}"
active()  { skipped "$1" && return 1; case " $RUN_LIST " in *" $1 "*) return 0;; *) return 1;; esac; }
hdr()     { echo -e "\n\033[1;36m═══ [$1] $2 ═══\033[0m"; echo -e "\n## [$1] $2\n" >> "$REPORT"; }
note()    { echo -e "\033[90m$1\033[0m"; echo "$1" >> "$REPORT"; }
find_()   { echo -e "\033[1;33m[+]\033[0m $1"; echo "- ⚠️ $1" >> "$REPORT"; }

T_XSS=180; T_SQLI=300; T_SSTI=240; T_NUCLEI=600
[[ $FAST -eq 1 ]] && { T_XSS=60; T_SQLI=120; T_SSTI=90; T_NUCLEI=180; }

CURL_OPTS=(-sk --max-time 15)
FFUF_H=(); ARJUN_H=""; SQLI_C=(); DALFOX_H=(); SSTI_C=(); NUCLEI_H=()
if [[ -n "$COOKIE" ]]; then
  FFUF_H=(-H "Cookie: $COOKIE"); ARJUN_H="Cookie: $COOKIE"
  SQLI_C=(--cookie "$COOKIE"); DALFOX_H=(-H "Cookie: $COOKIE")
  SSTI_C=(-c "$COOKIE"); NUCLEI_H=(-H "Cookie: $COOKIE")
fi

declare -A TOOL=( [dirs]=ffuf [params]=arjun [scan]=nuclei [xss]=dalfox [sqli]=sqlmap [ssti]=sstimap )

echo "# ctf-web-recon — $URL" > "$REPORT"
echo "- Data: $(date)" >> "$REPORT"
echo -e "\033[1;32m[ctf-wr]\033[0m target: $URL  →  out: $OUT"

# ─── Stato fasi e dipendenze (subito visibile, niente skip silenziosi) ──────
for p in $RUN_LIST; do
  t="${TOOL[$p]}"
  if skipped "$p"; then
    printf "  \033[90m%-7s saltata (--skip)\033[0m\n" "$p"
  elif have "$t"; then
    printf "  \033[32m%-7s\033[0m %s\n" "$p" "$t"
  elif [[ "$p" == params ]]; then
    printf "  \033[33m%-7s\033[0m solo form HTML (arjun mancante — install ctf-web-toolkit)\n" "$p"
  elif [[ "$p" == ssti ]]; then
    printf "  \033[33m%-7s\033[0m solo probe built-in (sstimap mancante — install ctf-web-toolkit)\n" "$p"
  else
    printf "  \033[31m%-7s SALTATA: %s mancante (install ctf-web-toolkit)\033[0m\n" "$p" "$t"
  fi
done

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
  python3 - "$URL" "$COOKIE" > "$OUT/forms.txt" 2>/dev/null << 'PY'
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
        local ARJ_ARGS=(-u "$ep" --stable -oJ "$OUT/params.json")
        [[ -n "$ARJUN_H" ]] && ARJ_ARGS+=(--headers "$ARJUN_H")
        timeout 120 arjun "${ARJ_ARGS[@]}" 2>/dev/null
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
  else
    hdr dirs "Directory discovery (ffuf)"
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
fi

# ─── Fase scan: nuclei ──────────────────────────────────────────────────────
if active scan; then
  if ! have nuclei; then note "scan: saltata (nuclei mancante)";
  else
    hdr scan "Vulnerability scan (nuclei)"
    timeout "$T_NUCLEI" nuclei -u "$URL" -severity critical,high,medium "${NUCLEI_H[@]}" \
        -silent -nc -o "$OUT/nuclei.txt" 2>/dev/null
    if [[ -s "$OUT/nuclei.txt" ]]; then cat "$OUT/nuclei.txt"; sed 's/^/- /' "$OUT/nuclei.txt" >> "$REPORT"
    else note "nessun finding"; fi
  fi
fi

# ─── Fase xss: dalfox ───────────────────────────────────────────────────────
if active xss; then
  if ! have dalfox; then note "xss: saltata (dalfox mancante)";
  else
    hdr xss "XSS scan (dalfox)"
    build_targets quick
    while read -r t; do
      note "test: $t"
      timeout "$T_XSS" dalfox url "$t" "${DALFOX_H[@]}" --silence --no-color --no-spinner 2>/dev/null \
        | tee -a "$OUT/xss.txt" | grep -Ei "\[POC\]|\[V\]" | head -5
    done < "$GET_T"
    while IFS=$'\t' read -r u d; do
      note "test (POST): $u"
      timeout "$T_XSS" dalfox url "$u" -X POST -d "$d" "${DALFOX_H[@]}" --silence --no-color --no-spinner 2>/dev/null \
        | tee -a "$OUT/xss.txt" | grep -Ei "\[POC\]|\[V\]" | head -5
    done < "$POST_T"
    if grep -qEi "\[POC\]|\[V\]" "$OUT/xss.txt" 2>/dev/null; then
      find_ "XSS trovato! vedi $OUT/xss.txt"
      grep -Ei "\[POC\]" "$OUT/xss.txt" | sed 's/^/  - /' >> "$REPORT"
    else note "nessun XSS confermato"; fi
  fi
fi

# ─── Fase sqli: sqlmap ──────────────────────────────────────────────────────
if active sqli; then
  if ! have sqlmap; then note "sqli: saltata (sqlmap mancante)";
  else
    hdr sqli "SQLi scan (sqlmap)"
    build_targets quick
    while read -r t; do
      note "test: $t"
      timeout "$T_SQLI" sqlmap -u "$t" "${SQLI_C[@]}" --batch --level 1 --risk 1 \
        --output-dir="$OUT/sqlmap" 2>/dev/null | tee -a "$OUT/sqli.txt" | grep -i "is vulnerable" | head -3
    done < "$GET_T"
    while IFS=$'\t' read -r u d; do
      note "test (POST): $u"
      timeout "$T_SQLI" sqlmap -u "$u" --data "$d" "${SQLI_C[@]}" --batch --level 1 --risk 1 \
        --output-dir="$OUT/sqlmap" 2>/dev/null | tee -a "$OUT/sqli.txt" | grep -i "is vulnerable" | head -3
    done < "$POST_T"
    if grep -qi "is vulnerable" "$OUT/sqli.txt" 2>/dev/null; then
      find_ "SQLi trovata! vedi $OUT/sqli.txt — approfondisci con: sqlmap -u TARGET --dbs"
    else note "nessuna SQLi confermata"; fi
  fi
fi

# ─── Fase ssti: probe built-in + sstimap ────────────────────────────────────
if active ssti; then
  hdr ssti "SSTI (probe built-in + sstimap)"
  build_targets quick

  # Probe built-in: funziona anche senza sstimap. Inietta marker aritmetici
  # in ogni parametro (GET e POST) e cerca il risultato valutato nel response.
  python3 - "$COOKIE" "$GET_T" "$POST_T" "$OUT/ssti-probe.txt" << 'PY'
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
    note "sstimap mancante — install ctf-web-toolkit per identificare il motore e sfruttare"
  else
    while read -r t; do
      note "sstimap: $t"
      timeout "$T_SSTI" sstimap -u "$t" "${SSTI_C[@]}" 2>/dev/null \
        | tee -a "$OUT/ssti.txt" | grep -Ei "injectable|engine" | head -3
    done < "$GET_T"
    while IFS=$'\t' read -r u d; do
      note "sstimap (POST): $u"
      timeout "$T_SSTI" sstimap -u "$u" --data "$d" "${SSTI_C[@]}" 2>/dev/null \
        | tee -a "$OUT/ssti.txt" | grep -Ei "injectable|engine" | head -3
    done < "$POST_T"
    if grep -qiE "is injectable|injection point" "$OUT/ssti.txt" 2>/dev/null; then
      find_ "SSTI confermata da sstimap! vedi $OUT/ssti.txt — exploit: sstimap -u TARGET --os-shell"
    elif [[ ! -s "$OUT/ssti-probe.txt" ]]; then
      note "nessuna SSTI confermata"
    fi
  fi
fi

# ─── Riepilogo ──────────────────────────────────────────────────────────────
echo -e "\n\033[1;36m═══ RIEPILOGO ═══\033[0m"
s=0
if [[ -s "$OUT/nuclei.txt" ]]; then echo "  scan:  $(grep -c . "$OUT/nuclei.txt") finding → nuclei.txt"; s=1; fi
if grep -qEi "\[POC\]|\[V\]" "$OUT/xss.txt" 2>/dev/null; then echo "  xss:   POC trovati → xss.txt"; s=1; fi
if grep -qi "is vulnerable" "$OUT/sqli.txt" 2>/dev/null; then echo "  sqli:  parametro vulnerabile → sqli.txt"; s=1; fi
if [[ -s "$OUT/ssti-probe.txt" ]]; then echo "  ssti:  $(grep -c . "$OUT/ssti-probe.txt") parametro/i valutano template → ssti-probe.txt"; s=1; fi
if grep -qiE "is injectable|injection point" "$OUT/ssti.txt" 2>/dev/null; then echo "  ssti:  confermata da sstimap → ssti.txt"; s=1; fi
[[ $s -eq 0 ]] && echo "  nessun finding confermato"
echo -e "  report: \033[1m$REPORT\033[0m"
note ""
note "---"
note "I finding vanno verificati a mano: i tool danno candidati, non flag."
