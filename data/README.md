# Banca domande del minigame

Il file `pentest_questions.json` è la fonte dati del minigioco PET. Può essere
modificato direttamente: SLWeb lo legge ogni volta che genera la pagina.
Con il server dinamico basta ricaricare `/pet/minigame`; per aggiornare la build
statica eseguire `python3 build_site.py`.

Ogni elemento di `questions` usa questo schema minimo:

```json
{
  "id": 501,
  "category": "Web Application Security",
  "topic": "OWASP Top 10",
  "difficulty": "Base",
  "type": "completion",
  "question": "Completa il comando: nmap ____ <IP>",
  "answer": "-sV",
  "accepted_answers": ["-sV"],
  "explanation": "Motivazione e principio decisivo",
  "tags": ["owasp"]
}
```

Per una domanda a crocette, impostare `type` a `multiple_choice` e aggiungere:

```json
"choices": [
  {"text": "Risposta A", "correct": false, "explanation": "Perché è errata"},
  {"text": "Risposta B", "correct": true,  "explanation": "Perché è corretta"}
]
```

Regole:

- `id` deve essere unico e numerico;
- `difficulty` deve essere `Base`, `Intermedio`, `Avanzato` o `EXTREME`;
- una domanda a scelta multipla deve avere almeno due opzioni e una sola corretta;
- una domanda `completion` deve contenere una sola sequenza `____`: il minigame
  la sostituisce con un input e confronta il testo con `answer` o con le varianti
  facoltative elencate in `accepted_answers`;
- `reference_answer` è facoltativo e permette di mostrare, dopo la verifica, il
  testo completo dal quale è stato rimosso il termine.

La banca contiene un nucleo di esercizi `Base` curati per profili junior. Le
nozioni molto specifiche sono classificate `EXTREME`. Per riapplicare il
riequilibrio e convertire eventuali vecchie risposte libere:

```bash
python3 scripts/rebalance_pentest_questions.py
```

Per reimportare in massa un file numerato e un TSV di risposte:

```bash
python3 scripts/import_pentest_questions.py domande.txt risposte.tsv
```
