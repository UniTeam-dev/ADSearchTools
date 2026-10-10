# Test-only Samba AD DC: domain CORP.LOCAL, LDAPS on 636, admin = Administrator@corp.local / Passw0rd!Test
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba samba-ad-provision samba-ad-dc openssl winbind krb5-user ldb-tools && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 636
ENTRYPOINT ["/entrypoint.sh"]
