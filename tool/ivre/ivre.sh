#!/usr/bin/env bash
# IVRE — stack manager per SeaLion.
# Gestisce i container Docker ufficiali ivre/db, ivre/web, ivre/client.
set -euo pipefail

IVRE_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE="$IVRE_HOME/ivre-share"
WEB_PORT="${IVRE_PORT:-2728}"

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
else
  DOCKER=(sudo docker)
fi

_need_daemon() {
  if ! "${DOCKER[@]}" info >/dev/null 2>&1; then
    echo "Demone Docker non raggiungibile." >&2
    echo "Avvialo con: sudo systemctl start docker" >&2
    exit 1
  fi
}

_client() {
  "${DOCKER[@]}" run --rm -it \
    --link ivredb:ivredb \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$SHARE":/ivre-share \
    ivre/client "$@"
}

cmd="${1:-help}"
[ $# -gt 0 ] && shift

case "$cmd" in
  up)
    _need_daemon
    "${DOCKER[@]}" start ivredb 2>/dev/null || \
      "${DOCKER[@]}" run -d --name ivredb ivre/db
    "${DOCKER[@]}" start ivreweb 2>/dev/null || \
      "${DOCKER[@]}" run -d --name ivreweb -p "$WEB_PORT":80 --link ivredb:ivredb ivre/web
    echo "IVRE web UI:  http://127.0.0.1:$WEB_PORT"
    ;;
  down)
    _need_daemon
    "${DOCKER[@]}" stop ivreweb ivredb
    ;;
  status)
    _need_daemon
    "${DOCKER[@]}" ps -a --filter name=ivre \
      --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    ;;
  init)
    "$0" up
    echo "Download dati GeoIP e inizializzazione database…"
    _client sh -c "ipdata --download && ivre scancli --init"
    echo "Fatto. Web UI: http://127.0.0.1:$WEB_PORT"
    ;;
  scan)
    target="${1:-}"
    if [ -z "$target" ]; then
      echo "Uso: ivre scan <target> [categoria]" >&2
      exit 1
    fi
    cat="${2:-SEALION}"
    case "$target$cat" in
      *"'"*|*';'*|*'$'*|*'`'*)
        echo "Target o categoria non validi." >&2
        exit 1
        ;;
    esac
    ts="$(date +%Y%m%d-%H%M%S)"
    out="/ivre-share/scans/$ts"
    echo "Scansione di $target — usa SOLO su target autorizzati."
    _client sh -c "mkdir -p '$out' && nmap -A -oX '$out/scan.xml' '$target' && ivre scan2db -c '$cat' -s SeaLion -r '$out' && ivre db2view"
    echo "Risultati importati. Apri http://127.0.0.1:$WEB_PORT"
    ;;
  shell)
    _client bash
    ;;
  web)
    xdg-open "http://127.0.0.1:$WEB_PORT" 2>/dev/null || \
      echo "http://127.0.0.1:$WEB_PORT"
    ;;
  help|--help|-h)
    cat <<EOF
IVRE — Shodan self-hosted (alternativa open source a Shodan/ZoomEye/Censys)
Gestione dello stack Docker (immagini ufficiali ivre/*).

Uso: ivre <comando>

  init                  Prima configurazione: up + download GeoIP + init DB
  up                    Avvia ivredb + ivreweb (web UI su porta $WEB_PORT)
  down                  Ferma i container
  status                Stato dei container IVRE
  scan <target> [cat]   nmap -A + import nel DB (SOLO target autorizzati!)
  shell                 Shell nel container client (ivre scancli, ipinfo, ...)
  web                   Apre la web UI nel browser

Dati condivisi con i container: $SHARE  (montata come /ivre-share)
Variabili: IVRE_PORT (default 2728)

Guida completa: slconsole -> help ivre
Docs ufficiali: https://doc.ivre.rocks
EOF
    ;;
  *)
    echo "Comando sconosciuto: $cmd (prova: ivre help)" >&2
    exit 1
    ;;
esac
