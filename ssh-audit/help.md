# ssh-audit — SSH Security Auditor

**ssh-audit** analizza la configurazione di un server SSH, mostrando algoritmi supportati, vulnerabilità note e raccomandazioni di sicurezza.

---

## A cosa serve?

- **Audit configurazione:** Verifica algoritmi di cifratura, MAC, key exchange
- **Vulnerabilità:** Segnala algoritmi deboli o deprecati
- **Compatibilità:** Mostra le versioni SSH supportate

---

## Come usarlo

### Audit di un server SSH

```bash
./ssh-audit.py 10.129.14.132
```

### Solo algoritmi

```bash
./ssh-audit.py -a 10.129.14.132
```

> Fonte: https://github.com/jtesta/ssh-audit
