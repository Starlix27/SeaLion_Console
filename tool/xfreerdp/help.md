# xfreerdp — Client RDP per Linux

**xfreerdp** è il client RDP open-source per Linux. Permette di connettersi al desktop remoto di macchine Windows (porta 3389) con supporto completo a NLA, TLS e clipboard condivisa.

---

## A cosa serve?

- **Desktop remoto:** Accesso alla GUI completa di Windows da Linux
- **Pentesting:** Connessione RDP dopo aver ottenuto credenziali valide
- **Montaggio cartelle:** Condivisione di cartelle locali con la macchina remota

---

## Come usarlo

### Connessione base

```bash
xfreerdp /v:<IP> /u:<username> /p:<password>
```

### Connessione con opzioni consigliate

```bash
xfreerdp /v:10.129.42.197 /u:user /p:'password' /cert:ignore /dynamic-resolution +clipboard
```

### Montare una cartella locale

```bash
xfreerdp /v:<IP> /u:user /p:'password' /drive:share,/tmp /cert:ignore
```

### Forzare TLS

```bash
xfreerdp /v:<IP> /u:user /p:'password' /sec:tls /cert:ignore
```

### Opzioni utili

| Opzione | Descrizione |
|---------|-------------|
| `/cert:ignore` | Ignora errori certificato autofirmato |
| `/dynamic-resolution` | Adatta risoluzione alla finestra |
| `+clipboard` | Abilita copia/incolla tra host e remoto |
| `/drive:nome,/path` | Monta una cartella locale nel desktop remoto |
| `/sec:tls` | Forza connessione TLS |
| `/f` | Modalità fullscreen |

> Fonte: https://github.com/FreeRDP/FreeRDP
