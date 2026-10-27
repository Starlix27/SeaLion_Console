# GTFOBins — database offline

Copia locale di [gtfobins.org](https://gtfobins.org): i one-liner per abusare dei binari Unix (shell, reverse shell, SUID, sudo, capabilities, file read/write) — la bibbia del privilege escalation, consultabile senza internet.

Uso dalla console:

    gtfobins find            tutte le funzioni note per il binario
    gtfobins find suid       solo i payload SUID
    gtfobins bash reverse-shell
    gtfobins search vim      cerca binari per nome
    gtfobins list            elenca tutti i binari nel database
    gtfobins update          aggiorna la copia locale (git pull)

Funzioni tipiche: shell, reverse-shell, bind-shell, command, privilege-escalation,
file-read, file-write, download, upload, library-load. Ogni payload indica i
contesti in cui funziona: sudo, suid, capabilities, unprivileged.

Fonte: https://gtfobins.org — https://github.com/GTFOBins/GTFOBins.github.io
