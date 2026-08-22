from __future__ import annotations

import argparse
import json
import random
import sys
import time
from datetime import date

from sealion import PET_FILE, GIF_FILE, print_sealsay, _play_ctrlc_gif


_PET_SAD_LINE = "Very Sad Sealion :("
_PET_HAPPY_LINES = ["Auh! Auh!", "*batte le pinne contento*", "*piroetta*", "Ouh! Ouh!"]
_PET_ANNOY_LINES = [
    "GRRRRRRR",
    "AAAAAAAAAAAAAAAA",
    "Gli hai rubato la coda... {name} non è felice",
    "{name} ti fissa male...",
    "*scappa sotto la console*",
    "Auh! Auh! AUH!",
]

_PET_SPIN_FRAMES = [
    [
        "   .--.",
        "  ( o  \\__",
        "   \\      \\",
        "    '--'-'",
    ],
    [
        "    .-.",
        "   ( o \\",
        "    \\__ \\",
        "     '-\\'",
    ],
    [
        "   .--.",
        " __/  o )",
        "/      /",
        "'-.__.-'",
    ],
    [
        "    .-.",
        "   / o )",
        "  / __/",
        " .'-/",
    ],
]


def _pet_help() -> None:
    print("""
  \033[95mpet\033[0m — il tuo sealion virtuale (non muore mai)

    pet                  Stato del sealion
    pet feed             Nutrisci (1 volta al giorno: AAAAAA)
    pet play             Gioca con lui (+felicità)
    pet annoy            Infastidisci (-5 felicità, GRRRRRRR)
    pet spin             Barrel roll in GIF (come Ctrl+C)
    pet say <testo>      Fai dire qualcosa al sealion
    pet game             Minigiochi (blackjack, indovina, wordle, 8ball)
    pet name <nome>      Rinomina il sealion

  Le statistiche partono al 50% e scendono piano ogni giorno, ma mai
  sotto lo 0%: peggio di così diventa solo un Very Sad Sealion :(
""")


def _pet_default() -> dict:
    return {"name": "SeaLion", "happiness": 50, "fullness": 50, "last_fed": "", "updated": 0.0}


def _pet_load() -> dict:
    pet = _pet_default()
    try:
        if PET_FILE.exists():
            data = json.loads(PET_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for key in list(pet):
                    if key in data:
                        pet[key] = data[key]
    except Exception:
        pass
    try:
        updated = float(pet.get("updated") or 0.0)
        elapsed = max(0.0, time.time() - updated) if updated > 0 else 0.0
        ticks = int(elapsed // 600)
    except Exception:
        ticks = 0
    if ticks > 0:
        pet["happiness"] = int(pet["happiness"]) - ticks
        pet["fullness"] = int(pet["fullness"]) - ticks
    pet["happiness"] = min(100, max(0, int(pet["happiness"])))
    pet["fullness"] = min(100, max(0, int(pet["fullness"])))
    return pet


def _pet_save(pet: dict) -> None:
    pet["updated"] = time.time()
    try:
        PET_FILE.parent.mkdir(parents=True, exist_ok=True)
        PET_FILE.write_text(json.dumps(pet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


def _pet_add(pet: dict, key: str, delta: int) -> None:
    pet[key] = min(100, max(0, int(pet[key]) + delta))


def _pet_bar(value: int, width: int = 22) -> str:
    filled = round(value / 100 * width)
    color = "\033[92m" if value >= 60 else "\033[93m" if value >= 30 else "\033[91m"
    return f"{color}{'█' * filled}\033[90m{'░' * (width - filled)}\033[0m"


def _pet_mood(pet: dict) -> str:
    h = int(pet["happiness"])
    if h >= 80:
        return "Estasiato"
    if h >= 60:
        return "Contento"
    if h >= 40:
        return "Ok"
    if h > 0:
        return "Triste"
    return _PET_SAD_LINE


def _pet_check_needs(pet: dict) -> list[str]:
    msgs: list[str] = []
    name = pet.get("name", "SeaLion")
    f = int(pet.get("fullness", 50))
    h = int(pet.get("happiness", 50))
    if f <= 0:
        msgs.append(f"{name} sta morendo di fame! → pet feed")
    elif f <= 10:
        msgs.append(f"{name} ha molta fame...")
    elif f <= 30:
        msgs.append(f"{name} ha fame.")
    if h <= 0:
        msgs.append(f"{name} è tristissimo! → pet play")
    elif h <= 10:
        msgs.append(f"{name} è molto triste...")
    elif h <= 30:
        msgs.append(f"{name} si annoia.")
    return msgs


def _pet_show(pet: dict) -> None:
    fed = str(pet.get("last_fed") or "mai")
    fed_today = fed == date.today().isoformat()
    print()
    print_sealsay(str(pet["name"]))
    print()
    print("  \033[95m┌─ SeaLion Pet ─────────────────────────────┐\033[0m")
    print(f"  Nome:         \033[1m{pet['name']}\033[0m")
    print(f"  Felicità      {_pet_bar(int(pet['happiness']))} {int(pet['happiness'])}%")
    print(f"  Sazietà       {_pet_bar(int(pet['fullness']))} {int(pet['fullness'])}%")
    print(f"  Umore:        \033[1m{_pet_mood(pet)}\033[0m")
    print(f"  Ultimo pasto: {fed}" + ("  \033[92m✓ oggi\033[0m" if fed_today else ""))
    print("  \033[95m└───────────────────────────────────────────┘\033[0m")
    if int(pet["happiness"]) == 0:
        print_sealsay(_PET_SAD_LINE)


def _pet_feed(pet: dict) -> None:
    today = date.today().isoformat()
    if pet.get("last_fed") != today:
        pet["last_fed"] = today
        _pet_add(pet, "fullness", 35)
        _pet_add(pet, "happiness", 15)
        _pet_save(pet)
        print_sealsay("AAAAAA")
        print("\n  \033[92m✓\033[0m Pasto giornaliero! (+35 sazietà, +15 felicità)")
    else:
        _pet_add(pet, "fullness", 5)
        _pet_save(pet)
        print_sealsay("*burp* ... hai già mangiato oggi!")
        print("\n  \033[92m✓\033[0m Spuntino extra (+5 sazietà)")


def _pet_play(pet: dict) -> None:
    _pet_add(pet, "happiness", 12)
    _pet_add(pet, "fullness", -6)
    _pet_save(pet)
    reaction = _PET_SAD_LINE if int(pet["happiness"]) == 0 else random.choice(_PET_HAPPY_LINES)
    print_sealsay(reaction)
    print(f"\n  \033[92m✓\033[0m Giocato con {pet['name']} (+12 felicità, -6 sazietà)")


def _pet_annoy(pet: dict) -> None:
    _pet_add(pet, "happiness", -5)
    _pet_save(pet)
    phrase = random.choice(_PET_ANNOY_LINES).format(name=pet["name"])
    print_sealsay(phrase)
    mood = f" · {pet['name']}: \033[1m{_pet_mood(pet)}\033[0m" if int(pet["happiness"]) > 0 else ""
    print(f"\n  \033[91m✗\033[0m Che noia! (-5 felicità{mood})")


def _pet_spin_action(pet: dict) -> None:
    if sys.stdin.isatty():
        _play_ctrlc_gif()
    else:
        for line in _PET_SPIN_FRAMES[0]:
            print(line)
        print("~ barrel roll ~")
    _pet_add(pet, "happiness", 6)
    _pet_save(pet)
    print(f"\n  \033[92m✓\033[0m {random.choice(_PET_HAPPY_LINES)}  (\033[95m+6 felicità\033[0m)")


def _pet_game_blackjack(pet: dict) -> bool | str | None:
    def card_value(card: str) -> int:
        if card in ("J", "Q", "K"):
            return 10
        if card == "A":
            return 11
        return int(card)

    def hand_total(hand: list[str]) -> int:
        total = sum(card_value(c) for c in hand)
        aces = hand.count("A")
        while total > 21 and aces:
            total -= 10
            aces -= 1
        return total

    def show_hand(label: str, hand: list[str], hide_second: bool = False) -> None:
        if hide_second and len(hand) >= 2:
            cards = f"\033[1m{hand[0]}\033[0m  \033[90m[?]\033[0m"
            print(f"  {label}: {cards}")
        else:
            cards = "  ".join(f"\033[1m{c}\033[0m" for c in hand)
            print(f"  {label}: {cards}  ({hand_total(hand)})")

    deck = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"] * 4
    random.shuffle(deck)
    player = [deck.pop(), deck.pop()]
    dealer = [deck.pop(), deck.pop()]

    print("\n  \033[96mBlackjack\033[0m contro il sealion!\n")
    show_hand("Tu     ", player)
    show_hand("Dealer ", dealer, hide_second=True)

    while hand_total(player) < 21:
        try:
            raw = input("\n  [h]it o [s]tand [q esci]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if raw in {"q", "quit", "exit"}:
            return None
        if raw in {"h", "hit"}:
            player.append(deck.pop())
            show_hand("Tu     ", player)
            show_hand("Dealer ", dealer, hide_second=True)
        elif raw in {"s", "stand"}:
            break
        else:
            print("  \033[93mScrivi h (hit) o s (stand).\033[0m")

    pt = hand_total(player)
    if pt > 21:
        show_hand("\n  Dealer ", dealer)
        print("  \033[91mSballato! Hai perso.\033[0m")
        return False

    print()
    show_hand("Tu     ", player)
    while hand_total(dealer) < 17:
        dealer.append(deck.pop())
    show_hand("Dealer ", dealer)
    dt = hand_total(dealer)

    if dt > 21:
        print("  \033[92mDealer sballato! Hai vinto!\033[0m")
        return True
    if pt > dt:
        print("  \033[92mHai vinto!\033[0m")
        return True
    if pt == dt:
        print("  \033[93mPareggio!\033[0m")
        return "draw"
    print("  \033[91mHa vinto il dealer!\033[0m")
    return False


def _pet_game_guess(pet: dict) -> bool | str | None:
    secret = random.randint(1, 100)
    max_tries = 7
    print(f"\n  \033[96mIndovina il numero\033[0m (1-100). Hai {max_tries} tentativi!")
    for attempt in range(1, max_tries + 1):
        try:
            raw = input(f"  [{attempt}/{max_tries}] Il tuo numero [q esci]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if raw in {"q", "quit", "exit"}:
            return None
        if not raw.isdigit() or not 1 <= int(raw) <= 100:
            print("  \033[93mInserisci un numero da 1 a 100.\033[0m")
            continue
        guess = int(raw)
        if guess == secret:
            print(f"  \033[92mEsatto! Era {secret}! Indovinato al tentativo {attempt}!\033[0m")
            return True
        if guess < secret:
            print(f"  \033[93mTroppo basso!\033[0m")
        else:
            print(f"  \033[93mTroppo alto!\033[0m")
    print(f"  \033[91mFiniti i tentativi! Il numero era {secret}.\033[0m")
    return False


_WORDLE_WORDS = [
    "amico", "bravo", "campo", "dente", "fuoco", "gatto", "hotel", "jolly",
    "karma", "lampo", "mango", "notte", "omega", "panda", "quasi", "rosso",
    "salto", "torre", "ultra", "vento", "yacht", "zaino", "album", "banca",
    "carne", "dolce", "freno", "globo", "igloo", "jumbo", "linea", "mondo",
    "nuoto", "osare", "piano", "quota", "ritmo", "sedia", "treno", "umore",
    "verde", "birra", "cielo", "dieta", "fango", "gonna", "input", "jeans",
    "lento", "media", "nervo", "opera", "perla", "radio", "spada", "tango",
    "volpe", "zebra", "acido", "buono", "corsa", "etnia", "fibra", "gente",
    "humus", "joker", "ladro", "miele", "onice", "porta", "razza", "sogno",
    "turbo", "usura", "vigna", "cover", "drago", "falco", "laser", "metro",
    "ninja", "olive", "pixel", "robot", "scala", "tigre", "virus", "ballo",
    "corda", "disco", "fonte", "gioco", "hobby", "isola", "libro", "mappa",
    "pizza", "sport", "tempo", "umido", "video", "bomba", "torta", "scudo",
    "menta", "fiore", "gusto", "nonna", "punto", "legno", "fuori", "vetro",
    "sonno", "barba", "carta", "ferro", "ruota", "volto", "morso", "polso",
    "serpe", "trama", "croce", "lungo", "mosca", "piuma", "ragno", "sfera",
    "notte", "brace", "acqua", "avena", "canto", "fosso", "grido", "lembo",
]

def _pet_game_wordle(pet: dict) -> bool | str | None:
    word = random.choice(_WORDLE_WORDS).lower()
    wlen = len(word)
    max_tries = 6
    print(f"\n  \033[96mWoordle\033[0m — Indovina la parola di {wlen} lettere! ({max_tries} tentativi)")
    print(f"  \033[92m█\033[0m = lettera giusta al posto giusto")
    print(f"  \033[93m█\033[0m = lettera giusta, posto sbagliato")
    print(f"  \033[90m█\033[0m = lettera non presente\n")

    for attempt in range(1, max_tries + 1):
        try:
            raw = input(f"  [{attempt}/{max_tries}] Parola ({wlen} lettere) [q esci]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if raw in {"q", "quit", "exit"}:
            return None
        if len(raw) != wlen:
            print(f"  \033[93mLa parola deve essere di {wlen} lettere.\033[0m")
            continue

        remaining = list(word)
        colors = [None] * wlen
        for i in range(wlen):
            if raw[i] == word[i]:
                colors[i] = "\033[92m"
                remaining[i] = None
        for i in range(wlen):
            if colors[i]:
                continue
            if raw[i] in remaining:
                colors[i] = "\033[93m"
                remaining[remaining.index(raw[i])] = None
            else:
                colors[i] = "\033[90m"
        display = "  "
        for i in range(wlen):
            display += f" {colors[i]}{raw[i].upper()}\033[0m"
        print(display)

        if raw == word:
            print(f"\n  \033[92mBravo! Indovinata in {attempt} tentativi!\033[0m")
            return True

    print(f"\n  \033[91mFiniti i tentativi! La parola era: \033[1m{word.upper()}\033[0m")
    return False


_8BALL_ANSWERS = [
    "Sicuramente sì!", "Senza dubbio.", "Molto probabile.",
    "Il sealion dice sì.", "Assolutamente!", "Le stelle dicono sì.",
    "Puoi contarci.", "È certo.", "Il destino sorride.",
    "Forse...", "Chiedi di nuovo.", "Non è chiaro.",
    "Il sealion sta pensando...", "Concentrati e richiedi.",
    "Non contarci.", "Il sealion dice no.", "Molto improbabile.",
    "Le stelle dicono di no.", "Assolutamente no.", "Non ci sperare.",
]

def _pet_game_8ball(pet: dict) -> bool | str | None:
    print("\n  \033[96m8Ball\033[0m — Fai una domanda al sealion e lui vedrà il futuro!")
    try:
        raw = input("  La tua domanda [q esci]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if raw.lower() in {"q", "quit", "exit"} or not raw:
        return None
    answer = random.choice(_8BALL_ANSWERS)
    print(f"\n  \033[95m🎱 {answer}\033[0m")
    return "draw"


_PET_GAMES = {
    "1": ("Blackjack", _pet_game_blackjack),
    "2": ("Indovina il numero", _pet_game_guess),
    "3": ("Wordle", _pet_game_wordle),
    "4": ("8Ball", _pet_game_8ball),
}


def _pet_games(pet: dict) -> None:
    while True:
        print("\n  \033[95mMinigiochi del SeaLion:\033[0m")
        for key, (label, _) in _PET_GAMES.items():
            print(f"    [{key}] {label}")
        print("    [q] Torna alla console")
        try:
            choice = input("  Scelta: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice in {"q", "quit", "exit", ""}:
            break
        if choice not in _PET_GAMES:
            print("  \033[93mScelta non valida.\033[0m")
            continue
        _, game = _PET_GAMES[choice]
        outcome = game(pet)
        if outcome is None:
            break
        if outcome is True:
            delta, note = 18, "+18 felicità"
        elif outcome == "draw":
            delta, note = 8, "+8 felicità"
        else:
            delta, note = 4, "+4 felicità"
        _pet_add(pet, "happiness", delta)
        _pet_save(pet)
        print(f"  \033[92m✓\033[0m {note} · felicità {int(pet['happiness'])}% · umore: {_pet_mood(pet)}")
        if int(pet["happiness"]) == 0:
            print_sealsay(_PET_SAD_LINE)


def cmd_pet(args: argparse.Namespace, state=None) -> int:
    action = getattr(args, "action", None)
    message = " ".join(getattr(args, "message", []) or []).strip()
    pet = _pet_load()

    if action in {"help", "-h", "--help"}:
        _pet_help()
        return 0
    if action in (None, "status"):
        _pet_show(pet)
        if action is None:
            print("\n  Azioni: \033[94mfeed\033[0m · \033[94mplay\033[0m · \033[94mannoy\033[0m · \033[94mspin\033[0m · \033[94msay <testo>\033[0m · \033[94mgame\033[0m · \033[94mname <nome>\033[0m · \033[94mhelp\033[0m")
        return 0
    if action == "feed":
        _pet_feed(pet)
        return 0
    if action == "play":
        _pet_play(pet)
        return 0
    if action == "annoy":
        _pet_annoy(pet)
        return 0
    if action == "spin":
        _pet_spin_action(pet)
        return 0
    if action == "say":
        print_sealsay(message or f"Auh! Sono {pet['name']}!")
        return 0
    if action == "game":
        _pet_games(pet)
        return 0
    if action == "name":
        if not message:
            print("Uso: pet name <nuovo nome>")
            return 1
        old = pet["name"]
        pet["name"] = message[:24]
        _pet_save(pet)
        print(f"  \033[92m✓\033[0m {old} si chiama ora \033[1m{pet['name']}\033[0m")
        return 0
    print(f"Azione pet sconosciuta: '{action}'. Vedi 'pet help'.")
    return 1
