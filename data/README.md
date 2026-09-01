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
  "type": "open_text",
  "question": "Testo della domanda",
  "answer": "Risposta di riferimento",
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
- `difficulty` deve essere `Base`, `Intermedio` o `Avanzato`;
- una domanda a scelta multipla deve avere almeno due opzioni e una sola corretta;
- una domanda `open_text` viene valutata dall'utente confrontandola con la risposta di riferimento.

Per reimportare in massa un file numerato e un TSV di risposte:

```bash
python3 scripts/import_pentest_questions.py domande.txt risposte.tsv
```
