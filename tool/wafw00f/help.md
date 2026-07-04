# wafw00f — WAF Detection Tool

Prima di attaccare, bisogna capire se c'è una guardia armata a proteggere il sito: un **WAF** (Web Application Firewall).

**wafw00f** identifica e rileva la presenza di un WAF davanti a un'applicazione web.

---

## A cosa serve?

- **Rilevare** se un sito è protetto da un Web Application Firewall
- **Identificare** quale WAF specifico è in uso (Cloudflare, Akamai, AWS WAF, ModSecurity, ecc.)
- Supporta oltre **200 WAF** diversi

> ⚠️ **Nota:** Usalo solo su target autorizzati.

---

## Come usarlo

### Scansione base

```bash
wafw00f http://www.esempio.com
```

### Testare tutti i WAF conosciuti

```bash
wafw00f http://www.esempio.com -a
```

### Elencare tutti i WAF supportati

```bash
wafw00f -l
```

### Output dettagliato

```bash
wafw00f http://www.esempio.com -v
```
