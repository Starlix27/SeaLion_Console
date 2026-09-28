---
title: "Report di Penetration Test"
lang: it
client: "{{CLIENT}}"
author: "Santarella Martina"
report-title: "{{RTYPE}}"
report-subtitle: "Report Finale"
date: "{{DATE}}"
version: "1.0"
classification: "Riservato"
---

<!-- ============================================================
     SLCtrl — Template Report di Penetration Test
     ------------------------------------------------------------
     USO:  report new          (wizard interattivo: cliente, box, date)
           report add <nome>   (aggiungi un finding)
           report edit <nome>  (apri in VS Code)
           report build <nome> (genera il PDF)
     ------------------------------------------------------------
     DATI DINAMICI — LEGGIMI!
     I blocchi racchiusi tra i marcatori  @@AUTO:nome@@ ... @@/AUTO:nome@@
     sono GENERATI AUTOMATICAMENTE da `report` / SLWeb (cliente,
     approccio, perimetro, conteggi severity, elenco e card finding).
     NON modificarli a mano: vengono sovrascritti a ogni sync.
     Per cambiarli usa `report add`, `report sync` o il wizard SLWeb.
     I blocchi racchiusi tra  @@SEZ:nome@@ ... @@/SEZ:nome@@
     contengono TESTO LIBERO: editabili qui o dal wizard SLWeb.
     ------------------------------------------------------------
     SEVERITA': <span class="sev sev-high">Alta</span>
       classi: sev-critical, sev-high, sev-medium, sev-low, sev-info
     ============================================================ -->

# Dichiarazione di Riservatezza

Il contenuto di questo documento è stato sviluppato da SLCtrl. SLCtrl considera
il contenuto di questo documento un'informazione proprietaria e riservata.
Queste informazioni devono essere utilizzate esclusivamente per gli scopi
previsti. Questo documento non può essere ceduto ad altri fornitori, partner
commerciali o collaboratori senza il preventivo consenso scritto di SLCtrl.
Inoltre, nessuna parte di questo documento può essere comunicata, riprodotta,
copiata o distribuita senza il previo consenso di SLCtrl.

Il contenuto di questo documento non costituisce consulenza legale. I servizi
offerti da SLCtrl relativi a conformità, contenziosi o altri interessi legali
non intendono costituire parere legale e non devono essere interpretati come
tali.

# Contatti

| **Contatti del Cliente** |                         |                             |
|--------------------------|-------------------------|-----------------------------|
| **Contatto Primario**    | **Ruolo**               | **Email Contatto Primario** |
| Mario Rossi              | Chief Executive Officer | mrossi@cliente.local        |
| **Contatto Secondario**  | **Ruolo**               | **Email Contatto Secondario** |
| Laura Bianchi            | Chief Technical Officer | lbianchi@cliente.local      |

: Tabella 1: Contatti del Cliente

| **Contatto SLCtrl** |                         |                             |
|---------------------|-------------------------|-----------------------------|
| **Nome**            | **Ruolo**               | **Email**                   |
| Santarella Martina  | Penetration Tester      | msantarella@slctrl.local    |

: Tabella 2: Contatto SLCtrl

# Executive Summary

{{CLIENT}} (di seguito "il Cliente") ha incaricato SLCtrl di eseguire
un {{RTYPE}}, al fine di identificare le debolezze di sicurezza, determinarne
l'impatto, documentare tutti i risultati in modo chiaro e ripetibile e fornire
raccomandazioni di remediation.

## Approccio

<!-- @@AUTO:approccio@@ -->
{{APPROCCIO}}
<!-- @@/AUTO:approccio@@ -->

## Perimetro

<!-- @@AUTO:perimetro@@ -->
{{PERIMETRO}}
<!-- @@/AUTO:perimetro@@ -->

## Panoramica e Raccomandazioni

<!-- @@AUTO:panoramica@@ -->
{{PANORAMICA}}
<!-- @@/AUTO:panoramica@@ -->

<!-- @@SEZ:panoramica_note@@ -->
<!-- Scrivi qui, in linguaggio non tecnico, i 3-5 problemi più importanti
     e la postura di sicurezza generale del Cliente. Chiudi rimandando
     alla sezione Piano di Remediation. -->
<!-- @@/SEZ:panoramica_note@@ -->

# Riepilogo dell'Assessment

SLCtrl ha iniziato tutte le attività di test dalla prospettiva di un utente non
autenticato sulla rete interna. Il Cliente ha fornito gli intervalli di rete,
senza informazioni aggiuntive su sistemi operativi o configurazioni.

## Riepilogo dei Finding

<!-- @@AUTO:riepilogo@@ -->
{{RIEPILOGO}}
<!-- @@/AUTO:riepilogo@@ -->

# Compromissione della Rete Interna

<!-- @@SEZ:compromissione@@ -->
Nel corso dell'assessment, SLCtrl è riuscita a ottenere un accesso iniziale
(foothold) e a compromettere la rete interna, arrivando al controllo
amministrativo completo del dominio {{DOMAIN}}. I passaggi seguenti illustrano
il percorso dall'accesso iniziale alla compromissione completa e non includono
tutte le vulnerabilità e misconfigurazioni individuate durante il test.
<!-- @@/SEZ:compromissione@@ -->

## Percorso di Attacco Dettagliato

<!-- @@SEZ:walkthrough@@ -->
<!-- Racconta qui la catena di attacco, un passaggio numerato per azione.
     Puoi includere output di comandi in blocchi ``` e screenshot:
     ![Figura 1: Decifratura hash](reports/{{SLUG}}/evidence/hashcat.png)
     Se lasci vuoto, questa sezione non comparirà nel PDF. -->
<!-- @@/SEZ:walkthrough@@ -->

# Piano di Remediation

## Breve Termine

<!-- @@SEZ:remediation_breve@@ -->
<!-- Azioni rapide ad alto impatto, una per riga con "- ".
     Se lasci vuoto, questa sezione non comparirà nel PDF. -->
<!-- @@/SEZ:remediation_breve@@ -->

## Medio Termine

<!-- @@SEZ:remediation_medio@@ -->
<!-- Azioni strutturali a medio termine, una per riga con "- ".
     Se lasci vuoto, questa sezione non comparirà nel PDF. -->
<!-- @@/SEZ:remediation_medio@@ -->

## Lungo Termine

<!-- @@SEZ:remediation_lungo@@ -->
<!-- Azioni a lungo termine (es. vulnerability assessment periodici,
     formazione). Se lasci vuoto, questa sezione non comparirà nel PDF. -->
<!-- @@/SEZ:remediation_lungo@@ -->

# Dettagli Tecnici dei Finding

<!-- I finding qui sotto sono generati automaticamente dai dati inseriti
     con `report add` o dal wizard SLWeb. NON modificarli a mano. -->

<!-- @@AUTO:findings@@ -->
{{FINDINGS}}
<!-- @@/AUTO:findings@@ -->

# Appendici

## Appendice A – Livelli di Severità

A ogni finding è stato assegnato un livello di severità, basato sulla priorità
con cui il finding dovrebbe essere affrontato e sul potenziale impatto su
riservatezza, integrità e disponibilità dei dati del Cliente.

| **Livello** | **Definizione** |
|-------------|-----------------|
| <span class="sev sev-critical">Critica</span> | Lo sfruttamento causa danni gravi; la compromissione immediata di sistemi o dati è probabile. Richiede remediation immediata. |
| <span class="sev sev-high">Alta</span> | Lo sfruttamento della vulnerabilità causa danni sostanziali. È probabile un danno significativo di natura operativa, finanziaria, legale e/o reputazionale. L'esposizione alla minaccia è elevata. |
| <span class="sev sev-medium">Media</span> | Lo sfruttamento può impattare significativamente riservatezza, integrità e/o disponibilità, ma esistono controlli di sicurezza in grado di contenere l'impatto; esposizione alla minaccia medio-alta. |
| <span class="sev sev-low">Bassa</span> | Lo sfruttamento causa un impatto minimo sulle operazioni. Esposizione alla minaccia medio-bassa e probabilità di occorrenza minima. |
| <span class="sev sev-info">Info</span> | Osservazione che non rappresenta di per sé una vulnerabilità, ma la cui risoluzione rafforzerebbe la postura di sicurezza complessiva. |

: Tabella 3: Definizioni dei Livelli di Severità

## Appendice B – Host Compromessi

<!-- @@SEZ:appendice_host@@ -->
<!-- Tabella degli host compromessi, es:
     | **Host**                | **Ambito** | **Metodo** | **Note**                  |
     |-------------------------|------------|------------|---------------------------|
     | `192.168.100.10 (DC01)` | Interno    | DCSync     | Compromissione del dominio |
     Se lasci vuoto, questa appendice non comparirà nel PDF. -->
<!-- @@/SEZ:appendice_host@@ -->

## Appendice C – Utenti Compromessi

<!-- @@SEZ:appendice_utenti@@ -->
<!-- Tabella degli account compromessi, es:
     | **Username** | **Tipo** | **Metodo**                     | **Note** |
     |--------------|----------|--------------------------------|----------|
     | `mrossi`     | Dominio  | NBT-NS/LLMNR Response Spoofing | Utente standard |
     Se lasci vuoto, questa appendice non comparirà nel PDF. -->
<!-- @@/SEZ:appendice_utenti@@ -->

## Appendice D – Modifiche e Bonifica degli Host

<!-- @@SEZ:appendice_bonifica@@ -->
<!-- Tabella delle modifiche/artefatti da bonificare, es:
     | **Host**                 | **Ambito** | **Modifica/Bonifica necessaria** |
     |--------------------------|------------|----------------------------------|
     | `192.168.100.20 (SQL01)` | Interno    | File caricato `cmd.aspx` — md5: `...` |
     Se lasci vuoto, questa appendice non comparirà nel PDF. -->
<!-- @@/SEZ:appendice_bonifica@@ -->

## Appendice E – Analisi delle Password del Dominio

<!-- @@SEZ:appendice_password@@ -->
<!-- Statistiche sul recupero delle password, es:
     | **Metrica**                   | **#**   |
     |-------------------------------|---------|
     | Hash di password ottenuti     | 2.000   |
     | Password recuperate in chiaro | 1.284   |
     Se lasci vuoto, questa appendice non comparirà nel PDF. -->
<!-- @@/SEZ:appendice_password@@ -->

# Considerazioni Finali

<!-- @@SEZ:considerazioni@@ -->
<!-- Considerazioni conclusive sulla postura di sicurezza del Cliente.
     Se lasci vuoto, questa sezione non comparirà nel PDF. -->
<!-- @@/SEZ:considerazioni@@ -->

<!-- @@AUTO:firma@@ -->
{{FIRMA}}
<!-- @@/AUTO:firma@@ -->
