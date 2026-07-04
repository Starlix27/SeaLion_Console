# rdp-sec-check — RDP Security Scanner

**rdp-sec-check** verifica le impostazioni di sicurezza di un server RDP, controllando cifratura, livello di autenticazione e NLA.

---

## A cosa serve?

- **Verifica cifratura:** Controlla il livello di encryption RDP
- **NLA Check:** Verifica se Network Level Authentication è attivo
- **Configurazioni errate:** Segnala impostazioni deboli

---

## Come usarlo

```bash
./rdp-sec-check.pl 10.129.201.248
```

> Fonte: https://github.com/CiscoCXSecurity/rdp-sec-check
