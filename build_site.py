#!/usr/bin/env python3
"""Build a static GitHub Pages site from SeaLion's http_server pages."""

from __future__ import annotations

import html
import json
import os
import random
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
BASE = os.environ.get("SITE_BASE_PATH", "/")
if not BASE.endswith("/"):
    BASE += "/"

# ---------------------------------------------------------------------------
# Mock `sealion` module so that `lib/pet.py` can be imported in CI
# ---------------------------------------------------------------------------
import types

_sealion_mock = types.ModuleType("sealion")
_sealion_mock.PET_FILE = Path("/dev/null")
_sealion_mock.GIF_FILE = Path("/dev/null")
_sealion_mock.print_sealsay = lambda *a, **k: None
_sealion_mock._play_ctrlc_gif = lambda *a, **k: None
sys.modules["sealion"] = _sealion_mock

# ---------------------------------------------------------------------------
# Now safe to import from the project
# ---------------------------------------------------------------------------
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

import http_server
from http_server import (
    _CSS,
    NOTES_ROOT,
    VULN_ROOT,
    TOOL_ROOT,
    _discover_notes,
    _discover_vulns,
    _discover_tools,
    _page_list,
    _page_md,
    _page_pet,
    _page_burp,
    _sl_version_hash,
)

VERSION_HASH = _sl_version_hash()

# ---------------------------------------------------------------------------
# Static _base_html — no server-only nav, client-side search
# ---------------------------------------------------------------------------
_STATIC_NAV_DOCS = [
    ("notes/", "Notes", "notes"),
    ("vuln/", "Vuln", "vuln"),
    ("tools/", "Tools", "tools"),
]
_STATIC_NAV_STANDALONE = [
    ("pet", "Pet", "pet"),
    ("burp", "BURP", "burp"),
]


def _base_html_static(title: str, body: str, active: str = "") -> str:
    docs_keys = {k for _, _, k in _STATIC_NAV_DOCS}
    home_cls = ' class="active"' if active == "home" else ""
    nav_html = f'<a href="{BASE}"{home_cls}>Home</a>\n'

    is_docs = active in docs_keys
    bcls = ' class="nav-drop-btn active"' if is_docs else ' class="nav-drop-btn"'
    nav_html += f'<div class="nav-drop"><span{bcls}>Docs ▾</span><div class="nav-drop-menu">'
    for href, label, key in _STATIC_NAV_DOCS:
        acls = ' class="active"' if key == active else ""
        nav_html += f'<a href="{BASE}{href}"{acls}>{label}</a>'
    nav_html += '</div></div>\n'

    for href, label, key in _STATIC_NAV_STANDALONE:
        cls = ' class="active"' if key == active else ""
        nav_html += f'<a href="{BASE}{href}"{cls}>{label}</a>\n'

    return f"""<!DOCTYPE html>
<html lang="it"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="base-path" content="{BASE}">
<title>{html.escape(title)} — SeaLion_Web</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/highlight.js@11/styles/github-dark.min.css">
<style>{_CSS}</style>
<script src="https://cdn.jsdelivr.net/npm/marked@15/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/highlight.js@11/lib/highlight.min.js"></script>
</head><body>
<div class="topbar">
<div class="topbar-left">
<a href="{BASE}" class="logo"><span class="prompt">$</span> SeaLion<span style="color:var(--text2);font-weight:400;font-size:12px">&nbsp;v{VERSION_HASH}</span></a>
<nav>{nav_html}</nav>
</div>
<div class="search-box">
<input type="text" id="global-search" placeholder="Cerca..." autocomplete="off" spellcheck="false">
<div class="search-results" id="search-results"></div>
</div>
</div>
{body}
<script>
(function(){{
  var B=document.querySelector('meta[name="base-path"]').content;
  var input=document.getElementById('global-search');
  var box=document.getElementById('search-results');
  var timer=null,idx=null;
  function loadIdx(){{
    if(idx)return Promise.resolve(idx);
    return fetch(B+'search-index.json').then(function(r){{return r.json();}}).then(function(d){{idx=d;return d;}});
  }}
  function esc(s){{var d=document.createElement('div');d.textContent=s;return d.innerHTML;}}
  function hl(text,q){{
    var e=esc(text),re=new RegExp('('+esc(q).replace(/[.*+?^${{}}()|[\\]\\\\]/g,'\\\\$&')+')','gi');
    return e.replace(re,'<mark>$1</mark>');
  }}
  function doSearch(){{
    var q=input.value.trim();
    if(q.length<2){{box.classList.remove('open');box.innerHTML='';return;}}
    loadIdx().then(function(data){{
      var ql=q.toLowerCase();
      var results=data.filter(function(d){{return d.name.toLowerCase().indexOf(ql)>=0||d.text.toLowerCase().indexOf(ql)>=0;}});
      if(!results.length){{box.innerHTML='<div class="sr-empty">Nessun risultato</div>';box.classList.add('open');return;}}
      var cats={{notes:'Notes',vuln:'Vuln',tools:'Tools'}};
      box.innerHTML=results.slice(0,20).map(function(r){{
        var href=B+r.href.replace(/^\\//, '')+'?q='+encodeURIComponent(q);
        return '<a class="sr-item" href="'+href+'">'+
          '<span class="sr-tag">'+(cats[r.section]||r.section)+'</span>'+
          '<span class="sr-name">'+hl(r.name,q)+'</span>'+
          '<span class="sr-ctx">'+hl(r.context||'',q)+'</span></a>';
      }}).join('');
      box.classList.add('open');
    }});
  }}
  input.addEventListener('input',function(){{clearTimeout(timer);timer=setTimeout(doSearch,250);}});
  input.addEventListener('focus',function(){{if(box.innerHTML)box.classList.add('open');}});
  document.addEventListener('click',function(e){{if(!e.target.closest('.search-box'))box.classList.remove('open');}});
  input.addEventListener('keydown',function(e){{
    if(e.key==='Escape'){{box.classList.remove('open');input.blur();}}
    if(e.key==='Enter'){{
      var first=box.querySelector('.sr-item');
      if(first)location.href=first.href;
      else if(input.value.trim().length>=2)location.href=B+'search/?q='+encodeURIComponent(input.value.trim());
    }}
  }});
}})();
</script>
</body></html>"""


# Monkey-patch
http_server._base_html = _base_html_static

# ---------------------------------------------------------------------------
# Static homepage
# ---------------------------------------------------------------------------

def _page_home_static() -> str:
    tips = http_server._load_tips()
    tip = random.choice(tips) if tips else "SeaLion"
    seal = html.escape(http_server._load_seal_art())
    wag_frames = http_server._load_wag_frames()
    wag_json = json.dumps(wag_frames)
    bark_frames = http_server._load_bark_frames()
    bark1_json = json.dumps(bark_frames[0])
    bark2_json = json.dumps(bark_frames[1])

    n_notes = len(_discover_notes())
    n_vulns = len(_discover_vulns())
    n_tools = len(_discover_tools())

    body = f"""
<div class="home-layout">
<div class="sidebar">
  <div class="info-box">
    <div class="label">Versione:</div>
    <div class="value">v{VERSION_HASH}</div>
  </div>
  <div class="info-box">
    <div class="label">GitHub:</div>
    <a href="https://github.com/Starlix27/SeaLion">github.com/Starlix27/SeaLion</a>
  </div>
  <div class="info-box">
    <div class="label">Creatrice:</div>
    <a href="https://github.com/Starlix27">@Starlix27</a>
  </div>
  <div class="info-box">
    <div class="label">Docs:</div>
    <ul class="cat-list">
      <li><a href="{BASE}notes/">Notes</a><span class="cnt">{n_notes} guide</span></li>
      <li><a href="{BASE}vuln/">Vuln</a><span class="cnt">{n_vulns} protocolli</span></li>
      <li><a href="{BASE}tools/">Tools</a><span class="cnt">{n_tools} tool</span></li>
    </ul>
  </div>
  <div class="info-box">
    <div class="label">Strumenti:</div>
    <ul class="cat-list">
      <li><a href="{BASE}pet">Pet</a><span class="cnt">sealion virtuale</span></li>
      <li><a href="{BASE}burp">BURP</a><span class="cnt">password profiler</span></li>
    </ul>
  </div>
  <div class="info-box" id="pet-widget" style="display:none">
    <div class="label">SeaLion Pet:</div>
    <div id="pet-home-name" class="value" style="cursor:pointer;color:var(--accent)" title="Apri Pet Portal"></div>
    <div id="pet-home-bars" style="margin-top:6px"></div>
  </div>
</div>
<div class="main-area">
  <div class="seal-container">
    <div class="seal-scene">
      <pre class="seal-art">{seal}</pre>
      <div class="seal-bubble-wrap">
        <div class="seal-bubble">{html.escape(tip)}</div>
      </div>
    </div>
  </div>
  <div class="terminal-input">
    <div id="term-output"></div>
    <div class="suggestions" id="suggestions"></div>
    <div class="prompt-line">
      <span class="user">user@slweb</span>:<span class="path">~</span>$&nbsp;
      <input type="text" id="term-input" placeholder="help, notes, vuln, tools..." autocomplete="off" spellcheck="false">
    </div>
  </div>
</div>
</div>
<script>
(function(){{
  var B=document.querySelector('meta[name="base-path"]').content;
  const cats=[
    {{name:'notes',label:'Notes',cnt:'{n_notes} guide',href:B+'notes/'}},
    {{name:'vuln',label:'Vuln',cnt:'{n_vulns} protocolli',href:B+'vuln/'}},
    {{name:'tools',label:'Tools',cnt:'{n_tools} tool',href:B+'tools/'}},
    {{name:'pet',label:'Pet',cnt:'sealion virtuale',href:B+'pet'}},
    {{name:'burp',label:'BURP',cnt:'password profiler',href:B+'burp'}},
  ];
  const input=document.getElementById('term-input');
  const box=document.getElementById('suggestions');
  const out=document.getElementById('term-output');
  let sel=-1;
  const hist=[];let hpos=-1;

  const HELP=
    '<span class="t-head">SeaLion Web — Comandi disponibili</span>\\n\\n'+
    '  <span class="t-section">— Docs</span>\\n'+
    '  <span class="t-accent">notes</span>       <span class="t-line">Apri le guide di pentesting ({n_notes} disponibili)</span>\\n'+
    '              <span class="t-line">Argomenti: footprinting, shells, password cracking, SSH, ecc.</span>\\n'+
    '  <span class="t-accent">vuln</span>        <span class="t-line">Apri le cheatsheet per protocollo ({n_vulns} protocolli)</span>\\n'+
    '              <span class="t-line">Ogni scheda ha: descrizione, porte, vuln comuni, comandi enum</span>\\n'+
    '  <span class="t-accent">tools</span>       <span class="t-line">Documentazione e help dei tool installabili ({n_tools})</span>\\n'+
    '              <span class="t-line">Ogni tool ha guida d\\'uso, opzioni principali ed esempi</span>\\n\\n'+
    '  <span class="t-section">— Strumenti</span>\\n'+
    '  <span class="t-accent">pet</span>         <span class="t-line">Pet Portal — nutri, gioca e cura il tuo sealion</span>\\n'+
    '              <span class="t-line">Feed, play, spin, annoy + mini-games (blackjack, wordle, 8ball)</span>\\n'+
    '  <span class="t-accent">burp</span>        <span class="t-line">BURP — Profiler password avanzato (sostituisce CUPP)</span>\\n'+
    '              <span class="t-line">Genera wordlist personalizzate basate sul profilo della vittima</span>\\n\\n'+
    '  <span class="t-section">— Terminale</span>\\n'+
    '  <span class="t-accent">help</span>        <span class="t-line">Mostra questo messaggio</span>\\n'+
    '  <span class="t-accent">help</span> <span class="t-line">&lt;cmd&gt;</span>  <span class="t-line">Dettagli su un comando (es. <span class="t-accent">help vuln</span>)</span>\\n'+
    '  <span class="t-accent">version</span>     <span class="t-line">Versione SLConsole</span>\\n'+
    '  <span class="t-accent">clear</span>       <span class="t-line">Pulisci il terminale</span>\\n';

  const CMD_HELP={{
    notes:
      '<span class="t-head">notes — Guide di Pentesting</span>\\n\\n'+
      '<span class="t-line">Apre la sezione con {n_notes} guide scritte su argomenti di pentesting.</span>\\n'+
      '<span class="t-line">Ogni guida copre metodologia, comandi utili e tool consigliati.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">notes</span> verrai portato alla pagina delle guide.</span>',
    vuln:
      '<span class="t-head">vuln — Cheatsheet Protocolli</span>\\n\\n'+
      '<span class="t-line">Apre la sezione con {n_vulns} cheatsheet, una per protocollo di rete.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">vuln</span> verrai portato alla pagina delle cheatsheet.</span>',
    tools:
      '<span class="t-head">tools — Documentazione Tool</span>\\n\\n'+
      '<span class="t-line">Apre la sezione con {n_tools} tool di sicurezza documentati.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">tools</span> verrai portato alla pagina dei tool.</span>',
    pet:
      '<span class="t-head">pet — SeaLion Pet Portal</span>\\n\\n'+
      '<span class="t-line">Apre il portale del tuo sealion virtuale.</span>\\n'+
      '<span class="t-line">Nutrilo, gioca, fallo girare e tienilo felice!</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">pet</span> verrai portato al Pet Portal.</span>',
    burp:
      '<span class="t-head">burp — BURP Password Profiler</span>\\n\\n'+
      '<span class="t-line">Genera wordlist personalizzate basate sul profilo della vittima.</span>\\n'+
      '<span class="t-line">Compila il form con info su target, famiglia, animali, azienda e keyword.</span>\\n\\n'+
      '<span class="t-line">Livelli: <span class="t-accent">fast</span> (~2k), <span class="t-accent">medium</span> (~15k), <span class="t-accent">full</span> (~100k+)</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">burp</span> verrai portato al BURP profiler.</span>',
    help:
      '<span class="t-head">help — Aiuto Comandi</span>\\n\\n'+
      '<span class="t-line">Mostra la lista dei comandi disponibili.</span>',
    clear:
      '<span class="t-head">clear — Pulisci Terminale</span>\\n\\n'+
      '<span class="t-line">Svuota l\\'output del terminale.</span>',
    version:
      '<span class="t-head">version — Versione</span>\\n\\n'+
      '<span class="t-line">Mostra la versione attuale di SeaLion Console.</span>',
  }};

  function echo(cmd,h){{
    out.innerHTML+=
      '<div class="t-entry"><span class="t-prompt">user@slweb</span>:<span class="t-accent">~</span>$ <span class="t-cmd">'+cmd+'</span></div>'+
      '<div class="t-entry">'+h+'</div>';
    out.scrollTop=out.scrollHeight;
  }}

  function run(raw){{
    const q=raw.trim();if(!q)return;
    hist.push(q);hpos=hist.length;
    const lo=q.toLowerCase();
    const parts=lo.split(' ').filter(Boolean);
    const nav=cats.find(c=>c.name===lo||c.label.toLowerCase()===lo);
    if(nav){{location.href=nav.href;return;}}
    if(parts[0]==='help'&&parts.length>1){{
      const sub=parts.slice(1).join(' ');
      const h=CMD_HELP[sub];
      if(h)echo(q,h);
      else echo(q,'<span class="t-line">Comando sconosciuto: <span class="t-accent">'+sub.replace(/</g,'&lt;')+'</span>. Scrivi <span class="t-accent">help</span> per la lista.</span>');
    }}
    else if(lo==='help'||lo==='?')echo(q,HELP);
    else if(lo==='clear')out.innerHTML='';
    else if(lo==='version')echo(q,'<span class="t-grn">SeaLion Console v{VERSION_HASH}</span>');
    else if(CMD_HELP[lo])echo(q,CMD_HELP[lo]);
    else echo(q,'<span class="t-line">Comando sconosciuto: '+q.replace(/</g,'&lt;')+'. Scrivi <span class="t-accent">help</span> per la lista.</span>');
    input.value='';box.classList.remove('open');
  }}

  function render(filtered){{
    if(!filtered.length){{box.classList.remove('open');return;}}
    box.innerHTML=filtered.map((c,i)=>
      `<div class="sug${{i===sel?' active':''}}" data-href="${{c.href}}" data-name="${{c.name}}">` +
      `<span class="sug-name">${{c.label}}</span><span class="sug-cnt">${{c.cnt}}</span></div>`
    ).join('');
    box.classList.add('open');
    box.querySelectorAll('.sug').forEach(el=>{{
      el.addEventListener('click',()=>{{
        const hr=el.dataset.href;
        if(hr&&hr!=='null')location.href=hr;
        else{{input.value='';box.classList.remove('open');run(el.dataset.name);}}
      }});
      el.addEventListener('mouseenter',()=>{{sel=[...box.children].indexOf(el);render(filtered);}});
    }});
  }}

  const allNames=[...cats.map(c=>c.name),'help','clear','version'];
  const helpSubs=Object.keys(CMD_HELP);
  function filter(){{
    const q=input.value.trim().toLowerCase();
    sel=-1;
    if(!q){{render(cats);return;}}
    if(q.startsWith('help ')&&q.length>5){{
      const sub=q.slice(5);
      const matched=helpSubs.filter(n=>n.startsWith(sub)).map(n=>{{
        return {{name:'help '+n,label:'help '+n,cnt:'Dettagli comando',href:null}};
      }});
      render(matched);return;
    }}
    const merged=allNames.filter(n=>n.startsWith(q)).map(n=>{{
      const c=cats.find(x=>x.name===n);if(c)return c;
      const lb={{help:'Mostra comandi',clear:'Pulisci terminale',version:'Versione'}};
      return {{name:n,label:n.charAt(0).toUpperCase()+n.slice(1),cnt:lb[n]||'',href:null}};
    }});
    render(merged);
  }}

  input.addEventListener('input',filter);
  input.addEventListener('focus',filter);
  input.addEventListener('keydown',e=>{{
    const items=box.querySelectorAll('.sug');
    const open=box.classList.contains('open')&&items.length;
    if(e.key==='ArrowDown'&&open){{e.preventDefault();sel=Math.min(sel+1,items.length-1);filter();}}
    else if(e.key==='ArrowUp'&&open){{e.preventDefault();sel=Math.max(sel-1,-1);filter();}}
    else if(e.key==='ArrowUp'&&!open){{e.preventDefault();if(hpos>0){{hpos--;input.value=hist[hpos];}}}}
    else if(e.key==='ArrowDown'&&!open){{e.preventDefault();if(hpos<hist.length-1){{hpos++;input.value=hist[hpos];}}}}
    else if(e.key==='Tab'&&items.length){{e.preventDefault();const t=items[Math.max(sel,0)];input.value=t.dataset.name;filter();}}
    else if(e.key==='Enter'){{
      e.preventDefault();
      const active=sel>=0&&items[sel]?items[sel]:null;
      if(active){{
        const hr=active.dataset.href;
        if(hr&&hr!=='null')location.href=hr;
        else run(active.dataset.name);
      }}else run(input.value);
    }}
  }});
  document.addEventListener('click',e=>{{if(!e.target.closest('.terminal-input'))box.classList.remove('open');}});
}})();
(function(){{
  var B=document.querySelector('meta[name="base-path"]').content;
  var w=document.getElementById('pet-widget');
  var raw=localStorage.getItem('sl_pet');
  if(!raw&&!w)return;
  try{{
    var pet=raw?JSON.parse(raw):{{name:'SeaLion',happiness:50,fullness:50,updated:0}};
    var u=parseFloat(pet.updated)||0;
    var el=u>0?Math.max(0,Date.now()/1000-u):0;
    var tk=Math.floor(el/600);
    var h=Math.max(0,Math.min(100,(pet.happiness||50)-tk));
    var f=Math.max(0,Math.min(100,(pet.fullness||50)-tk));
    if(!raw)localStorage.setItem('sl_pet',JSON.stringify(pet));
    var nm=document.getElementById('pet-home-name');
    nm.textContent=pet.name||'SeaLion';
    nm.onclick=function(){{location.href=B+'pet';}};
    var bar=function(l,v){{
      var c=v>=60?'var(--green)':v>=30?'var(--yellow)':'var(--red)';
      return '<div style="display:flex;align-items:center;gap:6px;margin:2px 0">'+
        '<span style="color:var(--text2);width:55px;font-size:11px">'+l+'</span>'+
        '<div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">'+
        '<div style="width:'+v+'%;height:100%;background:'+c+';border-radius:3px;transition:width .3s"></div>'+
        '</div><span style="font-size:11px;color:var(--text2);width:28px;text-align:right">'+v+'%</span></div>';
    }};
    document.getElementById('pet-home-bars').innerHTML=bar('Felicità',h)+bar('Sazietà',f);
    w.style.display='';
  }}catch(e){{}}
}})();
(function(){{
  var art=document.querySelector('.seal-art');
  if(!art)return;
  var orig=art.textContent;
  var frames={wag_json};
  var seq=[2,3,4,3,2,1,0,1];
  var tid=null,fi=0,barking=false;
  var barkFrame1={bark1_json};
  var barkFrame2={bark2_json};
  function wag(){{art.textContent=frames[seq[fi%seq.length]];fi++;}}
  function doBark(){{
    barking=true;art.textContent=orig;
    var bs=[barkFrame1,barkFrame2,barkFrame1,barkFrame2,barkFrame1,barkFrame2,barkFrame1,barkFrame2];
    var bi=0;
    var bt=setInterval(function(){{
      if(bi<bs.length){{art.textContent=bs[bi];bi++;}}
      else{{clearInterval(bt);art.textContent=orig;barking=false;}}
    }},200);
  }}
  function start(e){{e.preventDefault();if(tid||barking)return;fi=0;wag();tid=setInterval(wag,200);}}
  function stop(){{
    if(tid){{clearInterval(tid);tid=null;}}
    doBark();
  }}
  art.addEventListener('mousedown',start);
  art.addEventListener('mouseup',stop);
  art.addEventListener('mouseleave',function(){{if(tid){{clearInterval(tid);tid=null;}}art.textContent=orig;}});
  art.addEventListener('touchstart',start,{{passive:false}});
  art.addEventListener('touchend',stop);
}})();
</script>"""
    return _base_html_static("Home", body, active="home")


# ---------------------------------------------------------------------------
# Static search results page (client-side JS)
# ---------------------------------------------------------------------------
def _page_search_static() -> str:
    body = """<div class="container">
<div class="breadcrumb"><a href="/" id="sr-home">Home</a> <span>/</span> Ricerca</div>
<div class="page-title" id="sr-title">Ricerca</div>
<div class="page-sub" id="sr-sub"></div>
<div id="sr-results"></div>
</div>
<script>
(function(){
  var B=document.querySelector('meta[name="base-path"]').content;
  document.getElementById('sr-home').href=B;
  var params=new URLSearchParams(location.search);
  var q=params.get('q')||'';
  if(!q){document.getElementById('sr-title').textContent='Nessuna query';return;}
  document.getElementById('sr-title').textContent='Ricerca: '+q;
  fetch(B+'search-index.json').then(function(r){return r.json();}).then(function(data){
    var ql=q.toLowerCase();
    var results=data.filter(function(d){return d.name.toLowerCase().indexOf(ql)>=0||d.text.toLowerCase().indexOf(ql)>=0;});
    document.getElementById('sr-sub').textContent=results.length+' risultat'+(results.length===1?'o':'i');
    var cats={notes:'Notes',vuln:'Vuln',tools:'Tools'};
    function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}
    function hl(text){
      var e=esc(text),re=new RegExp('('+esc(q).replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&')+')','gi');
      return e.replace(re,'<mark>$1</mark>');
    }
    function ctx(text){
      var lines=text.split('\\n');
      for(var i=0;i<lines.length;i++){
        if(lines[i].toLowerCase().indexOf(ql)>=0){
          var s=lines[i].replace(/^#+\\s*/,'').trim();
          return s.length>120?s.substring(0,117)+'...':s;
        }
      }
      return '';
    }
    if(!results.length){
      document.getElementById('sr-results').innerHTML='<p style="color:var(--text2);text-align:center;padding:40px 0">Nessun risultato per "'+esc(q)+'"</p>';
      return;
    }
    document.getElementById('sr-results').innerHTML=results.map(function(r){
      var href=B+r.href.replace(/^\\//, '')+'?q='+encodeURIComponent(q);
      var c=ctx(r.text);
      return '<a href="'+href+'" style="text-decoration:none"><div class="search-page-item">'+
        '<div class="sp-header"><span class="sp-tag '+r.section+'">'+(cats[r.section]||r.section)+'</span>'+
        '<span class="sp-name">'+hl(r.name)+'</span></div>'+
        '<div class="sp-ctx">'+hl(c)+'</div></div></a>';
    }).join('');
  });
})();
</script>"""
    return _base_html_static("Ricerca", body)


# ---------------------------------------------------------------------------
# 404 page
# ---------------------------------------------------------------------------
def _page_404() -> str:
    body = """<div class="container" style="text-align:center;padding:80px 0">
<div class="page-title">404</div>
<div class="page-sub">Pagina non trovata</div>
<p style="margin-top:24px"><a href="/" id="lnk-home">Torna alla Home</a></p>
</div>
<script>document.getElementById('lnk-home').href=document.querySelector('meta[name="base-path"]').content;</script>"""
    return _base_html_static("404", body)


# ---------------------------------------------------------------------------
# Search index builder
# ---------------------------------------------------------------------------
def _build_search_index() -> list[dict]:
    index = []
    for stem, display in _discover_notes():
        md_file = NOTES_ROOT / f"{stem}.md"
        if not md_file.is_file():
            continue
        text = md_file.read_text(encoding="utf-8", errors="replace")
        index.append({"section": "notes", "name": display, "href": f"notes/{stem}/", "text": text})

    for stem, display in _discover_vulns():
        md_file = VULN_ROOT / f"{stem}.md"
        if not md_file.is_file():
            continue
        text = md_file.read_text(encoding="utf-8", errors="replace")
        index.append({"section": "vuln", "name": display, "href": f"vuln/{stem}/", "text": text})

    for tname, display in _discover_tools():
        help_f = TOOL_ROOT / tname / "help.md"
        if not help_f.exists():
            help_f = TOOL_ROOT / tname / "help.txt"
        if not help_f.exists():
            continue
        text = help_f.read_text(encoding="utf-8", errors="replace")
        index.append({"section": "tools", "name": display, "href": f"tools/{tname}/", "text": text})

    return index


# ---------------------------------------------------------------------------
# Write helper (applies base-path rewriting)
# ---------------------------------------------------------------------------
def _write(path: Path, content: str) -> None:
    if BASE != "/" and path.suffix in (".html",):
        PH_DQ, PH_SQ = "\x00DQ\x00", "\x00SQ\x00"
        content = content.replace(f'href="{BASE}', PH_DQ)
        content = content.replace(f"href='{BASE}", PH_SQ)
        content = content.replace('href="/', f'href="{BASE}')
        content = content.replace("href='/", f"href='{BASE}")
        content = content.replace(PH_DQ, f'href="{BASE}')
        content = content.replace(PH_SQ, f"href='{BASE}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main build
# ---------------------------------------------------------------------------
def build():
    out = PROJECT_ROOT / "site"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir()

    print(f"Building static site → {out}/")
    print(f"  Base path: {BASE}")
    print(f"  Version:   v{VERSION_HASH}")

    # .nojekyll
    _write(out / ".nojekyll", "")

    # Home
    _write(out / "index.html", _page_home_static())
    print("  ✓ index.html")

    # 404
    _write(out / "404.html", _page_404())
    print("  ✓ 404.html")

    # Notes
    notes = _discover_notes()
    _write(out / "notes" / "index.html", _page_list("Notes", "notes", notes))
    for stem, display in notes:
        md = (NOTES_ROOT / f"{stem}.md").read_text(encoding="utf-8", errors="replace")
        _write(out / "notes" / stem / "index.html", _page_md("notes", "Notes", stem, md))
    print(f"  ✓ notes/ ({len(notes)} pages)")

    # Vuln
    vulns = _discover_vulns()
    _write(out / "vuln" / "index.html", _page_list("Vuln", "vuln", vulns))
    for stem, display in vulns:
        md = (VULN_ROOT / f"{stem}.md").read_text(encoding="utf-8", errors="replace")
        _write(out / "vuln" / stem / "index.html", _page_md("vuln", "Vuln", stem, md))
    print(f"  ✓ vuln/ ({len(vulns)} pages)")

    # Tools
    tools = _discover_tools()
    descs: dict[str, str] = {}
    try:
        tool_json = PROJECT_ROOT / "sealion-tools.json"
        if tool_json.is_file():
            data = json.loads(tool_json.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict) and "desc" in v:
                        descs[k] = v["desc"]
    except Exception:
        pass
    _write(out / "tools" / "index.html", _page_list("Tools", "tools", tools, descs))
    for tname, display in tools:
        help_f = TOOL_ROOT / tname / "help.md"
        if not help_f.exists():
            help_f = TOOL_ROOT / tname / "help.txt"
        if not help_f.exists():
            continue
        md = help_f.read_text(encoding="utf-8", errors="replace")
        _write(out / "tools" / tname / "index.html", _page_md("tools", "Tools", tname, md))
    print(f"  ✓ tools/ ({len(tools)} pages)")

    # Pet
    _write(out / "pet" / "index.html", _page_pet())
    print("  ✓ pet/")

    # BURP
    _write(out / "burp" / "index.html", _page_burp())
    print("  ✓ burp/")

    # Search
    _write(out / "search" / "index.html", _page_search_static())
    index = _build_search_index()
    _write(out / "search-index.json", json.dumps(index, ensure_ascii=False))
    print(f"  ✓ search/ (index: {len(index)} docs)")

    total = 2 + (1 + len(notes)) + (1 + len(vulns)) + (1 + len(tools)) + 1 + 1 + 1
    print(f"\nDone! {total} HTML files + search-index.json")
    print(f"Preview: python3 -m http.server -d site 8080")


if __name__ == "__main__":
    build()
