"""BURP — Better User Research Password.

Password profiler avanzato che genera wordlist personalizzate
basate sul profilo della vittima.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PersonInfo:
    name: str = ""
    surname: str = ""
    nickname: str = ""
    birthdate: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "surname": self.surname,
                "nickname": self.nickname, "birthdate": self.birthdate}

    @classmethod
    def from_dict(cls, d: dict) -> "PersonInfo":
        return cls(name=d.get("name", ""), surname=d.get("surname", ""),
                   nickname=d.get("nickname", ""), birthdate=d.get("birthdate", ""))


@dataclass
class BurpProfile:
    first_name: str = ""
    last_name: str = ""
    nickname: str = ""
    birthdate: str = ""
    partners: list[PersonInfo] = field(default_factory=list)
    children: list[PersonInfo] = field(default_factory=list)
    siblings: list[PersonInfo] = field(default_factory=list)
    parents: list[PersonInfo] = field(default_factory=list)
    pets: list[str] = field(default_factory=list)
    company: str = ""
    keywords: list[str] = field(default_factory=list)
    min_length: int = 0
    max_length: int = 0
    allow_alpha: bool = True
    allow_upper: bool = True
    allow_digit: bool = True
    allow_special: bool = True

    def to_dict(self) -> dict:
        return {
            "first_name": self.first_name, "last_name": self.last_name,
            "nickname": self.nickname, "birthdate": self.birthdate,
            "partners": [p.to_dict() for p in self.partners],
            "children": [c.to_dict() for c in self.children],
            "siblings": [s.to_dict() for s in self.siblings],
            "parents": [p.to_dict() for p in self.parents],
            "pets": self.pets, "company": self.company,
            "keywords": self.keywords,
            "min_length": self.min_length, "max_length": self.max_length,
            "allow_alpha": self.allow_alpha,
            "allow_upper": self.allow_upper,
            "allow_digit": self.allow_digit,
            "allow_special": self.allow_special,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BurpProfile":
        def _people(key: str) -> list[PersonInfo]:
            pp = []
            for p in d.get(key, []):
                if isinstance(p, dict):
                    pi = PersonInfo.from_dict(p)
                    pi.birthdate = _normalize_date(pi.birthdate)
                    pp.append(pi)
            return pp
        return cls(
            first_name=d.get("first_name", ""),
            last_name=d.get("last_name", ""),
            nickname=d.get("nickname", ""),
            birthdate=_normalize_date(d.get("birthdate", "")),
            partners=_people("partners"),
            children=_people("children"),
            siblings=_people("siblings"),
            parents=_people("parents"),
            pets=[s for s in d.get("pets", []) if isinstance(s, str) and s.strip()],
            company=d.get("company", ""),
            keywords=[s for s in d.get("keywords", []) if isinstance(s, str) and s.strip()],
            min_length=int(d.get("min_length", 0) or 0),
            max_length=int(d.get("max_length", 0) or 0),
            allow_alpha=bool(d.get("allow_alpha", True)),
            allow_upper=bool(d.get("allow_upper", True)),
            allow_digit=bool(d.get("allow_digit", True)),
            allow_special=bool(d.get("allow_special", True)),
        )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1", "g": "9", "z": "2"}

SEPARATORS = ["", ".", "-", "_"]

COMMON_NUM_SUFFIXES = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "00", "01", "07", "10", "11", "12", "13", "21", "22", "23", "24", "25",
    "27", "42", "55", "66", "69", "77", "88", "89", "99",
    "000", "007", "100", "101", "123", "420", "666", "777", "911",
    "1234", "12345",
]

COMMON_NUM_PREFIXES = ["1", "12", "123", "007", "69"]

SPECIAL_SUFFIXES = ["!", "!!", "!?", "@", "#", "$", "*", "?", ".", "!!!", "!@",
                    "..", "!.", ".!", "?.", "!..", "..!", "@.", ".@", "#!", "!#"]
SPECIAL_PREFIXES = ["!", "@", "#", "$"]

MAX_PASSWORDS = 500_000

# ---------------------------------------------------------------------------
# Transformation helpers
# ---------------------------------------------------------------------------

def _case_variants(word: str) -> list[str]:
    if not word:
        return []
    variants = [word.lower()]
    titled = word.capitalize()
    if titled != variants[0]:
        variants.append(titled)
    upper = word.upper()
    if upper not in variants:
        variants.append(upper)
    if len(word) > 2:
        alt = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(word))
        if alt not in variants:
            variants.append(alt)
    return variants


def _leet_full(word: str) -> str:
    return "".join(_LEET.get(c, c) for c in word.lower())


def _leet_partial(word: str) -> list[str]:
    low = word.lower()
    results = []
    seen_positions: set[int] = set()
    for i, c in enumerate(low):
        if c in _LEET and i not in seen_positions:
            variant = low[:i] + _LEET[c] + low[i + 1:]
            if variant != low:
                results.append(variant)
            seen_positions.add(i)
    return results


def _initials(first: str, last: str) -> list[str]:
    if not first or not last:
        return []
    f, l_ = first[0].lower(), last[0].lower()
    F, L = f.upper(), l_.upper()
    return [f + l_, F + L, f + "." + l_ + ".", F + "." + L + ".",
            f + "." + l_, F + "." + L]


def _normalize_date(raw: str) -> str:
    clean = raw.replace("/", "").replace("-", "").replace(".", "").strip()
    if len(clean) == 8 and clean.isdigit():
        return clean[:2] + "/" + clean[2:4] + "/" + clean[4:]
    return raw.strip()


def _extract_date_parts(datestr: str) -> list[str]:
    if not datestr:
        return []
    datestr = _normalize_date(datestr)
    clean = datestr.replace("/", "").replace("-", "").replace(".", "").strip()
    parts: list[str] = []
    if len(clean) == 8:
        dd, mm = clean[:2], clean[2:4]
        yyyy = clean[4:8]
        yy = yyyy[2:]
        parts.extend([
            dd, mm, yyyy, yy,
            dd + mm, mm + dd,
            dd + mm + yyyy, dd + mm + yy,
            mm + dd + yyyy, mm + dd + yy,
            yyyy + mm + dd, yy + mm + dd,
            dd + yyyy, mm + yyyy,
        ])
    elif len(clean) == 4:
        parts.extend([clean, clean[2:]])
    elif len(clean) == 2:
        parts.append(clean)
    else:
        parts.append(clean)
    return list(dict.fromkeys(parts))


def _common_patterns(word: str) -> list[str]:
    cap = word.capitalize()
    return [
        cap + "123!", cap + "123", cap + "@123",
        cap + "!1", cap + "#1", cap + "1!",
        cap + "2024", cap + "2024!", cap + "2025", cap + "2025!",
        cap + "2026", cap + "2026!",
        word + "123!", word + "@123",
    ]


def _person_words(p: PersonInfo) -> list[str]:
    words: list[str] = []
    for val in (p.name, p.surname, p.nickname):
        v = val.strip()
        if v:
            words.append(v.lower())
            if v != v.lower():
                words.append(v)
    return list(dict.fromkeys(words))


# ---------------------------------------------------------------------------
# Word extraction
# ---------------------------------------------------------------------------

def _extract_words(profile: BurpProfile) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    target: list[str] = []
    for val in (profile.first_name, profile.last_name, profile.nickname):
        v = val.strip()
        if v:
            target.append(v.lower())
            if v != v.lower():
                target.append(v)
    groups["target"] = list(dict.fromkeys(target))
    groups["target_dates"] = _extract_date_parts(profile.birthdate)

    for i, p in enumerate(profile.partners):
        pw = _person_words(p)
        if pw:
            groups[f"partner_{i}"] = pw
            dates = _extract_date_parts(p.birthdate)
            if dates:
                groups[f"partner_{i}_dates"] = dates

    for i, c in enumerate(profile.children):
        cw = _person_words(c)
        if cw:
            groups[f"child_{i}"] = cw
            dates = _extract_date_parts(c.birthdate)
            if dates:
                groups[f"child_{i}_dates"] = dates

    for i, s in enumerate(profile.siblings):
        sw = _person_words(s)
        if sw:
            groups[f"sibling_{i}"] = sw
            dates = _extract_date_parts(s.birthdate)
            if dates:
                groups[f"sibling_{i}_dates"] = dates

    for i, p in enumerate(profile.parents):
        pw = _person_words(p)
        if pw:
            groups[f"parent_{i}"] = pw
            dates = _extract_date_parts(p.birthdate)
            if dates:
                groups[f"parent_{i}_dates"] = dates

    pets_list: list[str] = []
    for v in profile.pets:
        v = v.strip()
        if v:
            pets_list.append(v.lower())
            if v != v.lower():
                pets_list.append(v)
    if pets_list:
        groups["pet"] = list(dict.fromkeys(pets_list))

    if profile.company.strip():
        c = profile.company.strip()
        groups["company"] = list(dict.fromkeys([c.lower()] + ([c] if c != c.lower() else [])))

    kws_list: list[str] = []
    for k in profile.keywords:
        k = k.strip()
        if k:
            kws_list.append(k.lower())
            if k != k.lower():
                kws_list.append(k)
    if kws_list:
        groups["keywords"] = list(dict.fromkeys(kws_list))

    return groups


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def generate(profile: BurpProfile, level: str = "medium") -> Iterator[str]:
    words = _extract_words(profile)
    seen: set[str] = set()
    count = 0

    def _emit(candidate: str) -> Iterator[str]:
        nonlocal count
        if count >= MAX_PASSWORDS:
            return
        if not candidate or candidate in seen:
            return
        if profile.min_length and len(candidate) < profile.min_length:
            return
        if profile.max_length and len(candidate) > profile.max_length:
            return
        if not profile.allow_alpha and any(c.isalpha() for c in candidate):
            return
        if not profile.allow_upper and any(c.isupper() for c in candidate):
            return
        if not profile.allow_digit and any(c.isdigit() for c in candidate):
            return
        if not profile.allow_special and not candidate.isalnum():
            return
        seen.add(candidate)
        count += 1
        yield candidate

    word_keys = [k for k in words if not k.endswith("_dates")]
    all_base: list[str] = []
    for k in word_keys:
        all_base.extend(words[k])
    all_base = list(dict.fromkeys(all_base))

    all_dates: list[str] = []
    for k in words:
        if k.endswith("_dates"):
            all_dates.extend(words[k])
    all_dates = list(dict.fromkeys(all_dates))

    # ── FAST ──────────────────────────────────────────────────────────────
    DOUBLE_SPECIALS = ["!.", ".!", "..", "!!", "!?", "?.", "@!", "!@", "#!"]
    TRIPLE_SPECIALS = ["...", "!!!", "!..", "..!", "!?.", "!@!", "@!@"]
    for w in all_base:
        for cv in (w, w.capitalize(), w.upper()):
            yield from _emit(cv)
            for suffix in COMMON_NUM_SUFFIXES:
                yield from _emit(cv + suffix)
                for sp in SPECIAL_SUFFIXES:
                    yield from _emit(cv + suffix + sp)
                for ds in DOUBLE_SPECIALS:
                    yield from _emit(cv + suffix + ds)
                for ts in TRIPLE_SPECIALS:
                    yield from _emit(cv + suffix + ts)
                for s2 in COMMON_NUM_SUFFIXES:
                    if s2 != suffix and len(suffix) <= 2 and len(s2) <= 2:
                        yield from _emit(cv + suffix + s2)
            for sp in SPECIAL_SUFFIXES:
                yield from _emit(cv + sp)
                yield from _emit(sp + cv)
                for suffix in COMMON_NUM_SUFFIXES:
                    yield from _emit(cv + sp + suffix)

    for w in all_base:
        for d in all_dates:
            yield from _emit(w + d)
            yield from _emit(w.capitalize() + d)
            yield from _emit(d + w)
            yield from _emit(d + w.capitalize())
            for sp in SPECIAL_SUFFIXES:
                yield from _emit(w + d + sp)
                yield from _emit(w.capitalize() + d + sp)

    # Pure numeric / date combos (utile con allow_alpha=False)
    for d in all_dates:
        yield from _emit(d)
        for sp in SPECIAL_SUFFIXES:
            yield from _emit(d + sp)
        for n in COMMON_NUM_SUFFIXES:
            yield from _emit(d + n)
            yield from _emit(n + d)
    for i, d1 in enumerate(all_dates):
        for d2 in all_dates[i+1:]:
            yield from _emit(d1 + d2)
            yield from _emit(d2 + d1)

    for w in all_base:
        for p in _common_patterns(w):
            yield from _emit(p)

    # same-group pairs: first_name+last_name, first_name+nickname, etc.
    target_words = words.get("target", [])
    if len(target_words) >= 2:
        for a, b in itertools.permutations(target_words, 2):
            for sep in SEPARATORS:
                yield from _emit(a + sep + b)
                yield from _emit(a.capitalize() + sep + b)
                yield from _emit(a + sep + b.capitalize())
                yield from _emit(a.capitalize() + sep + b.capitalize())

    if level == "fast":
        return

    # ── MEDIUM ────────────────────────────────────────────────────────────
    # Cross-group combos
    for g1, g2 in itertools.combinations(word_keys, 2):
        for w1 in words[g1]:
            for w2 in words[g2]:
                for sep in SEPARATORS:
                    yield from _emit(w1 + sep + w2)
                    yield from _emit(w2 + sep + w1)
                    yield from _emit(w1.capitalize() + sep + w2)
                    yield from _emit(w1 + sep + w2.capitalize())
                    yield from _emit(w1.capitalize() + sep + w2.capitalize())
                    yield from _emit(w2.capitalize() + sep + w1)
                    yield from _emit(w2 + sep + w1.capitalize())
                    yield from _emit(w2.capitalize() + sep + w1.capitalize())

    # Cross-group + number suffixes
    for g1, g2 in itertools.combinations(word_keys, 2):
        for w1 in words[g1][:3]:
            for w2 in words[g2][:3]:
                combo = w1 + w2
                combo_cap = w1.capitalize() + w2.capitalize()
                for n in ("1", "12", "123", "!"):
                    yield from _emit(combo + n)
                    yield from _emit(combo_cap + n)

    # Partial leet
    for w in all_base:
        for lw in _leet_partial(w):
            yield from _emit(lw)
            cap = lw[0].upper() + lw[1:] if lw and lw[0].isalpha() else lw
            yield from _emit(cap)
            for suffix in ("1", "12", "123", "!", "123!"):
                yield from _emit(lw + suffix)
                yield from _emit(cap + suffix)

    # More case variants
    for w in all_base:
        for cv in _case_variants(w):
            yield from _emit(cv)
            for suffix in COMMON_NUM_SUFFIXES[:15]:
                yield from _emit(cv + suffix)

    # Prefix numbers/specials
    for w in all_base:
        for pre in COMMON_NUM_PREFIXES:
            yield from _emit(pre + w)
            yield from _emit(pre + w.capitalize())
        for sp in SPECIAL_PREFIXES:
            yield from _emit(sp + w)
            yield from _emit(sp + w.capitalize())

    # Middle insertions
    fn = profile.first_name.strip().lower()
    ln = profile.last_name.strip().lower()
    if fn and ln:
        for sep in SEPARATORS:
            for d in all_dates[:10]:
                yield from _emit(fn + sep + d + sep + ln)
                yield from _emit(fn.capitalize() + sep + d + sep + ln.capitalize())
                yield from _emit(fn + d + ln)
                yield from _emit(fn.capitalize() + d + ln.capitalize())
        for sp in ("!", "@", "#", "."):
            yield from _emit(fn + sp + ln)
            yield from _emit(fn.capitalize() + sp + ln.capitalize())

    # Initials
    if fn and ln:
        for init in _initials(fn, ln):
            yield from _emit(init)
            for suffix in COMMON_NUM_SUFFIXES[:20]:
                yield from _emit(init + suffix)
            for sp in SPECIAL_SUFFIXES[:5]:
                yield from _emit(init + sp)
            for d in all_dates[:5]:
                yield from _emit(init + d)

    # Each base word + each group's dates
    for gk in word_keys:
        date_key = gk + "_dates"
        if date_key not in words:
            continue
        for w in words[gk]:
            for d in words[date_key]:
                yield from _emit(w + d)
                yield from _emit(w.capitalize() + d)
                yield from _emit(d + w)

    if level == "medium":
        return

    # ── FULL ──────────────────────────────────────────────────────────────
    # Full leet
    for w in all_base:
        lw = _leet_full(w)
        yield from _emit(lw)
        for suffix in COMMON_NUM_SUFFIXES:
            yield from _emit(lw + suffix)
        for sp in SPECIAL_SUFFIXES:
            yield from _emit(lw + sp)
        for d in all_dates[:8]:
            yield from _emit(lw + d)

    # All 2-word permutations with case variants and separators
    for g1 in word_keys:
        for g2 in word_keys:
            if g1 == g2:
                continue
            for w1 in words[g1][:4]:
                for w2 in words[g2][:4]:
                    for sep in SEPARATORS:
                        for cv1 in _case_variants(w1):
                            for cv2 in _case_variants(w2):
                                yield from _emit(cv1 + sep + cv2)

    # Partial leet on cross-group combos
    for g1, g2 in itertools.combinations(word_keys, 2):
        for w1 in words[g1][:3]:
            for w2 in words[g2][:3]:
                combo = w1 + w2
                for lw in _leet_partial(combo):
                    yield from _emit(lw)
                    yield from _emit(lw.capitalize())
                combo_r = w2 + w1
                for lw in _leet_partial(combo_r):
                    yield from _emit(lw)

    # Reversed words
    for w in all_base:
        rev = w[::-1]
        yield from _emit(rev)
        yield from _emit(rev.capitalize())
        for suffix in COMMON_NUM_SUFFIXES:
            yield from _emit(rev + suffix)
        for sp in SPECIAL_SUFFIXES:
            yield from _emit(rev + sp)

    # Doubled words
    for w in all_base:
        yield from _emit(w + w)
        yield from _emit(w.capitalize() + w.capitalize())

    # 3-part combos: word + date + special
    for w in all_base:
        for d in all_dates:
            for sp in SPECIAL_SUFFIXES:
                yield from _emit(w.capitalize() + d + sp)
                yield from _emit(w + d + sp)

    # prefix + word + suffix
    for w in all_base:
        for pre_sp in SPECIAL_PREFIXES:
            for suffix in COMMON_NUM_SUFFIXES:
                yield from _emit(pre_sp + w + suffix)
                yield from _emit(pre_sp + w.capitalize() + suffix)

    # Full leet on cross-group combos
    for g1, g2 in itertools.combinations(word_keys, 2):
        for w1 in words[g1][:3]:
            for w2 in words[g2][:3]:
                yield from _emit(_leet_full(w1 + w2))
                yield from _emit(_leet_full(w2 + w1))
                yield from _emit(_leet_full(w1) + w2)
                yield from _emit(w1 + _leet_full(w2))


# ---------------------------------------------------------------------------
# Public API for web
# ---------------------------------------------------------------------------

def generate_from_dict(profile_dict: dict, level: str = "medium") -> list[str]:
    if level not in ("fast", "medium", "full"):
        level = "medium"
    profile = BurpProfile.from_dict(profile_dict)
    return list(generate(profile, level))


def estimate_counts(profile_dict: dict) -> dict[str, int]:
    profile = BurpProfile.from_dict(profile_dict)
    return {lvl: sum(1 for _ in generate(profile, lvl)) for lvl in ("fast", "medium", "full")}


# ---------------------------------------------------------------------------
# CLI interview
# ---------------------------------------------------------------------------

def _ask_text(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"  {prompt}{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return val or default


def _ask_yn(prompt: str, default: bool = False) -> bool:
    hint = "S/[n]" if default else "[s]/N" if not default else "s/n"
    try:
        val = input(f"  {prompt} ({hint}): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not val:
        return default
    return val.startswith("s") or val.startswith("y")


def _ask_multi_person(role: str) -> list[PersonInfo]:
    people: list[PersonInfo] = []
    idx = 1
    while True:
        print(f"\n  \033[90m[{role} #{idx}]\033[0m")
        name = _ask_text(f"Nome del {role} (invio per saltare)")
        if not name:
            break
        surname = _ask_text(f"Cognome del {role}", default="")
        nickname = _ask_text(f"Soprannome del {role}", default="")
        birthdate = _normalize_date(_ask_text(f"Data di nascita (GGMMAAAA)", default=""))
        people.append(PersonInfo(name=name, surname=surname,
                                 nickname=nickname, birthdate=birthdate))
        idx += 1
    return people


def _interview() -> tuple[BurpProfile, str] | None:
    try:
        from sealion import print_sealsay
        print_sealsay("BURP — Better User Research Password")
    except Exception:
        print("\n  BURP — Better User Research Password\n")

    print(f"\n  \033[92m{'─' * 52}\033[0m")
    print(f"  \033[92;1m  BURP\033[0m  \033[90m— password profiler avanzato\033[0m")
    print(f"  \033[92m{'─' * 52}\033[0m\n")
    print("  Inserisci le informazioni sul target.")
    print("  Premi invio per saltare un campo.\n")

    # 1. Target
    print("  \033[92;1m[1] Target\033[0m")
    first = _ask_text("Nome")
    if not first:
        print("  \033[91mNome obbligatorio.\033[0m")
        return None
    last = _ask_text("Cognome")
    nick = _ask_text("Soprannome / nick")
    birth = _normalize_date(_ask_text("Data di nascita (GGMMAAAA)"))

    # 2. Partner
    print("\n  \033[92;1m[2] Partner\033[0m")
    partners = _ask_multi_person("partner")

    # 3. Figli
    print("\n  \033[92;1m[3] Figli\033[0m")
    children = _ask_multi_person("figlio/a")

    # 4. Fratelli/Sorelle
    print("\n  \033[92;1m[4] Fratelli / Sorelle\033[0m")
    siblings = _ask_multi_person("fratello/sorella")

    # 5. Genitori
    print("\n  \033[92;1m[5] Genitori\033[0m")
    parents = _ask_multi_person("genitore")

    # 6. Animali
    print("\n  \033[92;1m[6] Animali domestici\033[0m")
    pets_raw = _ask_text("Nomi (separati da virgola)")
    pets = [p.strip() for p in pets_raw.split(",") if p.strip()] if pets_raw else []

    # 7. Azienda
    print("\n  \033[92;1m[7] Lavoro\033[0m")
    company = _ask_text("Azienda / luogo di lavoro")

    # 8. Keywords
    print("\n  \033[92;1m[8] Parole chiave extra\033[0m")
    kw_raw = _ask_text("Hobby, squadra, ecc. (separate da virgola)")
    keywords = [k.strip() for k in kw_raw.split(",") if k.strip()] if kw_raw else []

    # 9. Policy
    print("\n  \033[92;1m[9] Filtro policy password\033[0m")
    print("  \033[90m  (spuntato = includi quel tipo, no = escludi)\033[0m")
    min_len = _ask_text("Lunghezza minima", default="0")
    max_len = _ask_text("Lunghezza massima (0 = nessun limite)", default="0")
    allow_alpha = _ask_yn("Includi password con lettere?", default=True)
    allow_upper = _ask_yn("Includi password con maiuscole?", default=True)
    allow_digit = _ask_yn("Includi password con numeri?", default=True)
    allow_special = _ask_yn("Includi password con caratteri speciali?", default=True)

    # 10. Level
    print("\n  \033[92;1m[10] Livello di generazione\033[0m")
    print("    \033[93m1\033[0m) Fast     — ~500-2k password (combo base)")
    print("    \033[93m2\033[0m) Medium   — ~2k-15k (cross-group, leet parziale, prefissi)")
    print("    \033[93m3\033[0m) Full     — ~15k-100k+ (tutto: permutazioni, leet, reverse)")
    level_in = _ask_text("Scegli [1/2/3]", default="2")
    level_map = {"1": "fast", "2": "medium", "3": "full",
                 "fast": "fast", "medium": "medium", "full": "full"}
    level = level_map.get(level_in.lower(), "medium")

    profile = BurpProfile(
        first_name=first, last_name=last, nickname=nick, birthdate=birth,
        partners=partners, children=children, siblings=siblings, parents=parents,
        pets=pets, company=company, keywords=keywords,
        min_length=int(min_len) if min_len.isdigit() else 0,
        max_length=int(max_len) if max_len.isdigit() else 0,
        allow_alpha=allow_alpha,
        allow_upper=allow_upper,
        allow_digit=allow_digit,
        allow_special=allow_special,
    )
    return profile, level


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _write_wordlist(profile: BurpProfile, level: str, outfile: str) -> int:
    count = 0
    with open(outfile, "w", encoding="utf-8") as f:
        for pw in generate(profile, level):
            f.write(pw + "\n")
            count += 1
    return count


# ---------------------------------------------------------------------------
# CLI handler
# ---------------------------------------------------------------------------

def cmd_burp(args: argparse.Namespace, state=None) -> int:
    profile_file = getattr(args, "profile", None)
    if profile_file:
        try:
            with open(profile_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            profile = BurpProfile.from_dict(data)
            level = "medium"
        except Exception as e:
            print(f"  \033[91mErrore lettura profilo: {e}\033[0m")
            return 1
    else:
        result = _interview()
        if result is None:
            return 0
        profile, level = result

    if getattr(args, "fast", False):
        level = "fast"
    elif getattr(args, "full", False):
        level = "full"

    target_name = profile.first_name.strip().lower() or "target"
    outfile = getattr(args, "output", None) or f"{target_name}_burp.txt"

    print(f"\n  \033[92mCalcolo stime...\033[0m")
    counts = {}
    for lvl in ("fast", "medium", "full"):
        counts[lvl] = sum(1 for _ in generate(profile, lvl))
    print(f"  \033[90m  fast:   {counts['fast']:>8,} password\033[0m")
    print(f"  \033[90m  medium: {counts['medium']:>8,} password\033[0m")
    print(f"  \033[90m  full:   {counts['full']:>8,} password\033[0m")

    print(f"\n  \033[92mGenerazione in corso... (livello: \033[93m{level}\033[92m)\033[0m")

    count = _write_wordlist(profile, level, outfile)

    print(f"\n  \033[92m[+] Wordlist generata: {outfile}\033[0m")
    print(f"  \033[92m[+] {count:,} password candidate\033[0m")
    print(f"  \033[92m{'─' * 52}\033[0m\n")

    return 0
