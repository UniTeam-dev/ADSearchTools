#!/bin/sh
set -e
T=/var/lib/samba/private/tls-test
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision --realm=CORP.LOCAL --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass='Passw0rd!Test' --use-rfc2307
  samba-tool domain passwordsettings set --account-lockout-threshold=3 --account-lockout-duration=30 --reset-account-lockout-after=30
  # Internal-CA-style cert (CORP-ROOT-CA), valid for dc01.corp.local, localhost and 127.0.0.1
  mkdir -p $T && cd $T
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=CORP-ROOT-CA" -keyout ca.key -out ca.pem 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=dc01.corp.local" -keyout key.pem -out req.csr 2>/dev/null
  printf "subjectAltName=DNS:dc01.corp.local,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > ext.cnf
  openssl x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -extfile ext.cnf -out cert.pem 2>/dev/null
  chmod 600 key.pem
  sed -i "/\[global\]/a \\\ttls enabled = yes\n\ttls keyfile = $T/key.pem\n\ttls certfile = $T/cert.pem\n\ttls cafile = $T/ca.pem" /etc/samba/smb.conf
fi
exec samba -i --debug-stdout
