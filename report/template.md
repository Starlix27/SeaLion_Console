---
title: "Report di Penetration Test"
lang: it
client: "Nome Cliente S.r.l."
author: "Santarella Martina"
report-title: "Penetration Test Interno"
report-subtitle: "Report Finale"
date: "28 settembre 2026"
version: "1.0"
classification: "Riservato"
---

<!-- ============================================================
     SLCtrl — Template Report di Penetration Test
     ------------------------------------------------------------
     USO:  report new "Nome Cliente"   (crea una copia)
           report edit <nome>          (apri in VS Code)
           report build <nome>         (genera il PDF)
     ------------------------------------------------------------
     SEVERITA': <span class="sev sev-high">Alta</span>
       classi: sev-critical, sev-high, sev-medium, sev-low, sev-info
     CARD FINDING: tabella a due colonne dentro ::: {.finding}
       NB: la riga dei trattini definisce le proporzioni delle
       colonne (etichetta ~28% / valore ~72%) — mantienila simile.
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

Nome Cliente S.r.l. (di seguito "il Cliente") ha incaricato SLCtrl di eseguire
un Penetration Test della rete interna, al fine di identificare le debolezze di
sicurezza, determinarne l'impatto, documentare tutti i risultati in modo
chiaro e ripetibile e fornire raccomandazioni di remediation.

## Approccio

SLCtrl ha eseguito il test con approccio "black box" dal *DATA INIZIO* al
*DATA FINE*, senza credenziali né conoscenza preliminare dell'ambiente interno
del Cliente, con l'obiettivo di identificare debolezze sconosciute. Il test è
stato condotto in modalità non evasiva, con l'obiettivo di scoprire il maggior
numero possibile di misconfigurazioni e vulnerabilità.

<!-- Descrivi: tipo di approccio (black/grey/white box), finestra temporale,
     modalità (evasiva/non evasiva), obiettivi (foothold, dominio...),
     azioni consentite (movimento laterale, privilege escalation, ecc.) -->

## Perimetro

Il perimetro di questo assessment comprende una subnet di rete interna e il
dominio Active Directory CLIENTE.LOCAL.

| **Host/URL/Indirizzo IP** | **Descrizione**           |
|---------------------------|---------------------------|
| `192.168.100.0/24`        | Rete interna del Cliente  |

: Tabella 3: Dettagli del Perimetro

## Panoramica e Raccomandazioni

Durante il penetration test interno, SLCtrl ha identificato *N* finding che
minacciano la riservatezza, l'integrità e la disponibilità dei sistemi
informativi del Cliente. I finding sono stati classificati per livello di
severità: *N* ad alto rischio, *N* a rischio medio e *N* a rischio basso.

<!-- Riassumi qui, in linguaggio non tecnico, i 3-5 problemi più importanti
     e la postura di sicurezza generale. Chiudi rimandando alla sezione
     Piano di Remediation. -->

# Riepilogo dell'Assessment

SLCtrl ha iniziato tutte le attività di test dalla prospettiva di un utente non
autenticato sulla rete interna. Il Cliente ha fornito gli intervalli di rete,
senza informazioni aggiuntive su sistemi operativi o configurazioni.

## Riepilogo dei Finding

Nel corso del test, SLCtrl ha rilevato un totale di *N* finding che
rappresentano un rischio concreto per i sistemi informativi del Cliente. La
tabella seguente riassume i finding per livello di severità.

| **Critica** | **Alta** | **Media** | **Bassa** | **Totale** |
|-------------|----------|-----------|-----------|------------|
| 0           | 2        | 1         | 1         | 4          |

: Tabella 4: Riepilogo per Severità

Di seguito una panoramica di alto livello di ciascun finding identificato.
I finding sono trattati in dettaglio nella sezione *Dettagli Tecnici dei
Finding* di questo report.

| **#** | **Severità** | **Nome del Finding**                        |
|-------|--------------|---------------------------------------------|
| 1.    | <span class="sev sev-high">Alta</span>     | LLMNR/NBT-NS Response Spoofing          |
| 2.    | <span class="sev sev-high">Alta</span>     | Autenticazione Kerberos debole ("Kerberoasting") |
| 3.    | <span class="sev sev-medium">Media</span>  | Condivisioni di rete non sicure         |
| 4.    | <span class="sev sev-low">Bassa</span>     | Directory listing abilitato             |

: Tabella 5: Elenco dei Finding

# Compromissione della Rete Interna

Nel corso dell'assessment, SLCtrl è riuscita a ottenere un accesso iniziale
(foothold) e a compromettere la rete interna, arrivando al controllo
amministrativo completo del dominio Active Directory CLIENTE.LOCAL. I passaggi
seguenti illustrano il percorso dall'accesso iniziale alla compromissione
completa e non includono tutte le vulnerabilità e misconfigurazioni
individuate durante il test.

## Percorso di Attacco Dettagliato

Per compromettere completamente il dominio CLIENTE.LOCAL sono stati eseguiti
i seguenti passaggi:

1. È stato utilizzato il tool `Responder` per catturare l'hash NTLMv2 di un
   utente di dominio, `mrossi`.
2. L'hash è stato decifrato offline con `hashcat`, ottenendo la password in
   chiaro dell'utente e quindi un accesso iniziale al dominio CLIENTE.LOCAL.
3. È stato quindi eseguito `bloodhound-python` per enumerare il dominio e
   mappare i percorsi di attacco, identificando un account con Service
   Principal Name (SPN) vulnerabile a Kerberoasting.
4. *...continua la catena di attacco, un passaggio numerato per azione...*

Di seguito i passaggi dettagliati per riprodurre la catena di attacco:

```
$ sudo responder -I eth0 -wrfv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[+] Listening for events...
[SNIP]
```

*Figura 1: Cattura dell'hash NTLMv2 con Responder*

<!-- SUGGERIMENTO: puoi includere screenshot invece/oltre all'output testuale:
     ![Figura 2: Decifratura dell'hash con Hashcat](reports/<cliente>/evidence/hashcat.png)
-->

# Piano di Remediation

A seguito di questo assessment, il Cliente ha diverse opportunità per
rafforzare la sicurezza della rete interna. Le attività di remediation sono
elencate in ordine di priorità, partendo da quelle che richiedono
presumibilmente meno tempo e sforzo.

## Breve Termine

- [Finding 2] – Impostare password robuste (24+ caratteri) su tutti gli account SPN
- Imporre il cambio password a tutti gli utenti a seguito della compromissione del dominio

## Medio Termine

- [Finding 1] – Disabilitare LLMNR e NBT-NS ovunque possibile
- [Finding 2] – Migrare dagli account SPN ai Group Managed Service Accounts (gMSA)
- [Finding 3] – Eseguire un audit delle condivisioni di rete

## Lungo Termine

- Eseguire vulnerability assessment interni e audit delle password di dominio con cadenza regolare
- Formare gli amministratori di sistema sulle best practice di hardening
- Migliorare la segmentazione di rete per isolare gli host critici e limitare
  gli effetti di una compromissione interna

# Dettagli Tecnici dei Finding

<!-- Duplica il blocco seguente per ogni finding. Mantieni lo stesso ordine. -->

## SLC-01 – LLMNR/NBT-NS Response Spoofing – <span class="sev sev-high">Alta</span>

::: {.finding}
|                     | |
|---------------------|-------------------------------------------------------|
| **CWE**             | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| **Punteggio CVSS 3.1** | 9.5 |
| **Descrizione (incl. causa)** | Rispondendo al traffico di rete LLMNR/NBT-NS, un attaccante può impersonare una fonte autorevole per la risoluzione dei nomi, forzando la comunicazione con un sistema sotto il proprio controllo. LLMNR e NBT-NS sono abilitati di default sugli host Windows e sono risultati attivi sulla rete del Cliente. |
| **Impatto**         | Un attaccante presente sulla rete locale può avvelenare le risposte di risoluzione dei nomi (poisoning) e catturare hash NTLMv2, che possono essere decifrati offline o sfruttati in attacchi di relay per ottenere accesso non autorizzato ai sistemi. |
| **Asset Interessati** | `CLIENTE.LOCAL` |
| **Remediation**     | Disabilitare LLMNR e NetBIOS nelle impostazioni di sicurezza locali o tramite Group Policy, se non necessari. Abilitare SMB Signing per bloccare gli attacchi di relay NTLMv2. Utilizzare segmentazione di rete e sistemi IDS/IPS per rilevare attività di poisoning. |
| **Riferimenti**     | <https://attack.mitre.org/techniques/T1557/001/> |
:::

**Evidenze:**

Esecuzione del tool `Responder` per catturare gli hash di password degli utenti:

```
$ sudo responder -I eth0 -wrfv
[SNIP]
[SMB] NTLMv2-SSP Client   : 192.168.100.55
[SMB] NTLMv2-SSP Username : CLIENTE\mrossi
[SMB] NTLMv2-SSP Hash     : mrossi::CLIENTE:7eccXXXXXXXX98ebc:73d1b2c8...
[SNIP]
```

*Figura 2: Esecuzione di Responder*

---

## SLC-02 – Autenticazione Kerberos Debole ("Kerberoasting") – <span class="sev sev-high">Alta</span>

::: {.finding}
|                     | |
|---------------------|-------------------------------------------------------|
| **CWE**             | [CWE-521](https://cwe.mitre.org/data/definitions/521.html) |
| **Punteggio CVSS 3.1** | 8.1 |
| **Descrizione (incl. causa)** | Gli account di servizio configurati con Service Principal Names (SPN) utilizzano password deboli e facilmente indovinabili. Qualsiasi utente di dominio autenticato può richiedere ticket Kerberos TGS per questi account e decifrarli offline. |
| **Impatto**         | La decifratura della password di un account di servizio può consentire movimento laterale o privilege escalation, potenzialmente fino alla compromissione completa del dominio, poiché gli account di servizio spesso dispongono di privilegi elevati. |
| **Asset Interessati** | `svc-sql@CLIENTE.LOCAL` |
| **Remediation**     | Impostare password robuste (24+ caratteri) generate casualmente su tutti gli account SPN; migrare ai Group Managed Service Accounts (gMSA) dove possibile. |
| **Riferimenti**     | <https://attack.mitre.org/techniques/T1558/003/> |
:::

**Evidenze:**

```
$ GetUserSPNs.py CLIENTE.LOCAL/mrossi -dc-ip 192.168.100.10 -request-user svc-sql
[SNIP]
$krb5tgs$23$*svc-sql$CLIENTE.LOCAL$CLIENTE.LOCAL/svc-sql*$2c43cf68f96543...
[SNIP]
```

*Figura 3: Kerberoasting con GetUserSPNs.py*

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

: Tabella 6: Definizioni dei Livelli di Severità

## Appendice B – Host Compromessi

| **Host**                | **Ambito** | **Metodo**                             | **Note**                  |
|-------------------------|------------|----------------------------------------|---------------------------|
| `192.168.100.10 (DC01)` | Interno    | DCSync                                 | Compromissione del dominio |
| `192.168.100.20 (SQL01)`| Interno    | NBT-NS/LLMNR Spoofing, Kerberoasting   | Accesso iniziale           |

: Tabella 7: Dettagli degli Host Compromessi

## Appendice C – Utenti Compromessi

| **Username** | **Tipo** | **Metodo**                     | **Note**                |
|--------------|----------|--------------------------------|-------------------------|
| `mrossi`     | Dominio  | NBT-NS/LLMNR Response Spoofing | Utente di dominio standard |
| `svc-sql`    | Dominio  | Kerberoasting                  | Admin locale su SQL01   |

: Tabella 8: Account Compromessi

## Appendice D – Modifiche e Bonifica degli Host

| **Host**                 | **Ambito** | **Modifica/Bonifica necessaria**                          |
|--------------------------|------------|-----------------------------------------------------------|
| `192.168.100.20 (SQL01)` | Interno    | File caricato `cmd.aspx` in `C:\inetpub\wwwroot\` — md5: `5391c4a8af1ede757ba9d28865e75853` |

: Tabella 9: Artefatti dell'Assessment

## Appendice E – Analisi delle Password del Dominio

### Statistiche Generali

| **Metrica**                                | **#**   |
|--------------------------------------------|---------|
| Hash di password ottenuti                  | 2.000   |
| Password recuperate in chiaro              | 1.284   |
| % di password recuperate                   | 64,2%   |
| Numero di Domain Admin                     | 12      |
| Password di Domain Admin recuperate        | 5       |
| % di password di Domain Admin recuperate   | 42%     |

: Tabella 10: Statistiche sul Recupero delle Password

### Password più Utilizzate

| **Password**   | **#** |
|----------------|-------|
| `Benvenuto1`   | 22    |
| `Password123`  | 10    |
| `Primavera2026`| 8     |

: Tabella 11: Password più Utilizzate

# Considerazioni Finali

<!-- Spazio per osservazioni conclusive: postura di sicurezza complessiva,
     priorità strategiche, suggerimenti sui prossimi passi (retest, formazione,
     assessment periodici), ecc. -->

Nel complesso, l'assessment ha evidenziato che *...inserire considerazioni
conclusive sulla postura di sicurezza del Cliente...*

SLCtrl rimane a disposizione per chiarimenti sui contenuti di questo report e
per pianificare le attività di remediation e un eventuale retest.

<div class="signature">
<img src="report/assets/firma.png" alt="Firma"><br>
<span class="sig-name">Santarella Martina</span><br>
<span class="sig-role">Penetration Tester — SLCtrl</span>
</div>
