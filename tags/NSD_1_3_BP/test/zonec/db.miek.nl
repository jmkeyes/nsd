;
; BIND data file for miek.nl for internal use
;
$TTL    1H
@       IN      SOA     elektron.atoom.net. miekg.atoom.net. (
                     2002120700         ; Serial
                             6H         ; Refresh
                             2H         ; Retry
                             7D         ; Expire
                             1H )       ; Negative Cache TTL

@       IN      NS      elektron.atoom.net.
@	IN	MX	10 elektron.atoom.net.
@	IN	A	192.168.1.2

a	IN	A	192.168.1.2
www     IN      CNAME   a
smtp    IN      CNAME   a
mail    IN      CNAME   a

; extra stuff to fight spam
frodo	IN	MX	10 elektron.atoom.net.
gandalf	IN	MX	10 elektron.atoom.net.