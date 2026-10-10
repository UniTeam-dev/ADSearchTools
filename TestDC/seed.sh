#!/bin/sh
# Demo data matching the design mockups. Run: docker cp seed.sh photo.b64 adsearch-testdc:/ && docker exec adsearch-testdc sh /seed.sh
set -e
B="DC=corp,DC=local"
PW='Passw0rd!User'
for ou in "OU=Company" "OU=IT,OU=Company" "OU=Sales,OU=Company" "OU=HR,OU=Company" "OU=Archive,OU=HR,OU=Company"; do
  samba-tool ou add "$ou,$B" >/dev/null 2>&1 || true
done
u() { # sam given surname ou title
  samba-tool user add "$1" "$PW" --given-name="$2" --surname="$3" --userou="$4" --job-title="$5" --department="$6" --mail-address="$1@corp.local" >/dev/null 2>&1 || true
}
u a.belov "Артём" "Белов" "OU=IT,OU=Company" "Сетевой инженер" IT
u p.ivanov "Пётр" "Иванов" "OU=IT,OU=Company" "DevOps-инженер" IT
u m.kuznetsova "Мария" "Кузнецова" "OU=IT,OU=Company" "Системный аналитик" IT
u d.orlova "Дарья" "Орлова" "OU=IT,OU=Company" "Инженер поддержки" IT
u o.petrov "Олег" "Петров" "OU=IT,OU=Company" "Системный администратор" IT
u a.smirnova "Анна" "Смирнова" "OU=IT,OU=Company" "Руководитель IT" IT
u o.ivanova "Ольга" "Иванова" "OU=HR,OU=Company" "Специалист по кадрам" HR
u i.sorokina "Ирина" "Сорокина" "OU=HR,OU=Company" "HR-бизнес-партнёр" HR
u d.ivanchenko "Дмитрий" "Иванченко" "OU=Sales,OU=Company" "Менеджер по продажам" Sales
u p.solovyov "Павел" "Соловьёв" "OU=Sales,OU=Company" "Руководитель продаж" Sales
samba-tool user disable o.petrov >/dev/null
samba-tool group add IT-Admins --groupou="OU=IT,OU=Company" --description="Администраторы ИТ-инфраструктуры" >/dev/null 2>&1 || true
samba-tool group add VPN-Users --groupou="OU=Company" --description="Доступ к корпоративному VPN" >/dev/null 2>&1 || true
samba-tool group add IT-Department --groupou="OU=IT,OU=Company" --group-scope=Universal --group-type=Distribution >/dev/null 2>&1 || true
samba-tool group addmembers IT-Admins a.belov,p.ivanov,o.petrov,a.smirnova >/dev/null
samba-tool group addmembers VPN-Users a.belov,p.ivanov,a.smirnova,d.orlova,d.ivanchenko,p.solovyov,o.ivanova >/dev/null
samba-tool computer add IT-LT-042 --description="MacBook Pro, Смирнова А." >/dev/null 2>&1 || true
samba-tool computer add SALES-PC-07 --description="Отдел продаж" >/dev/null 2>&1 || true
samba-tool computer add HR-PC-02 --description="Отдел кадров" >/dev/null 2>&1 || true
IT="OU=IT,OU=Company,$B"
dn() { echo "CN=$1,$IT"; }
cat > /tmp/seed.ldif <<LDIF
dn: $(dn "Пётр Иванов")
changetype: modify
replace: displayName
displayName: Иванов Пётр
-
replace: telephoneNumber
telephoneNumber: +7 495 123-45-67, доб. 214
-
replace: mobile
mobile: +7 916 555-12-34
-
replace: manager
manager: $(dn "Анна Смирнова")
-
replace: description
description: Инфраструктура, CI/CD

dn: $(dn "Анна Смирнова")
changetype: modify
replace: displayName
displayName: Смирнова Анна
-
replace: thumbnailPhoto
thumbnailPhoto:: $(cat /photo.b64)

dn: $(dn "Артём Белов")
changetype: modify
replace: displayName
displayName: Белов Артём

dn: $(dn "Мария Кузнецова")
changetype: modify
replace: displayName
displayName: Кузнецова Мария
-
replace: pwdLastSet
pwdLastSet: 0

dn: $(dn "Дарья Орлова")
changetype: modify
replace: displayName
displayName: Орлова Дарья

dn: $(dn "Олег Петров")
changetype: modify
replace: displayName
displayName: Петров Олег
-
replace: description
description: Уволен 30.09.2026, заявка HR-1182

dn: CN=IT-LT-042,CN=Computers,$B
changetype: modify
replace: operatingSystem
operatingSystem: macOS
-
replace: operatingSystemVersion
operatingSystemVersion: 26.0 (25A354)
-
replace: dNSHostName
dNSHostName: it-lt-042.corp.local

dn: CN=SALES-PC-07,CN=Computers,$B
changetype: modify
replace: operatingSystem
operatingSystem: Windows 11 Pro
LDIF
ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/seed.ldif >/dev/null
echo seeded
