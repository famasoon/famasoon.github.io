---
title: "Samba enumeration"
date: "2023-01-08"
draft: "false"
---

# Samba

samba

```
$ cat /etc/samba/smb.conf | grep -v "#\|\;"[global]
   workgroup = DEV.INFREIGHT.HTB
   server string = DEVSMB
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes

   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

[print$]   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
```

| 設定 | 説明 |
| --- | --- |
| [sharename] | ネットワーク共有の名前。 |
| workgroup = WORKGROUP/DOMAIN | クライアントがクエリを実行したときに表示されるワークグループ。 |
| path = /path/here/ | ユーザーにアクセス権を付与するディレクトリ。 |
| server string = STRING | 接続が開始されたときに表示される文字列。 |
| unix password sync = yes | UNIX パスワードを SMB パスワードと同期しますか? |
| usershare allow guests = yes | 認証されていないユーザーが、定義された共有にアクセスすることを許可しますか? |
| map to guest = bad user | ユーザーのログイン要求が有効な UNIX ユーザーと一致しない場合はどうすればよいですか? |
| browseable = yes | この共有を利用可能な共有のリストに表示する必要がありますか? |
| guest ok = yes | パスワードを使用せずにサービスに接続できるようにしますか? |
| read only = yes | ユーザーにファイルの読み取りのみを許可しますか? |
| create mask = 0700 | 新しく作成されたファイルにはどのような権限を設定する必要がありますか? |

| browseable = yes | 現在の共有で利用可能な共有をリストすることを許可しますか? |
| --- | --- |
| read only = no | ファイルの作成と変更を禁止しますか? |
| writable = yes | ユーザーにファイルの作成と変更を許可しますか? |
| guest ok = yes | パスワードを使用せずにサービスに接続できるようにしますか? |
| enable privileges = yes | 特定の SID に割り当てられた特権を尊重しますか? |
| create mask = 0777 | 新しく作成されたファイルにはどのようなアクセス許可を割り当てる必要がありますか? |
| directory mask = 0777 | 新しく作成されたディレクトリに割り当てる必要のあるアクセス許可は何ですか? |
| logon script = script.sh | ユーザーのログイン時にどのスクリプトを実行する必要がありますか? |
| magic script = script.sh | スクリプトが閉じられたときにどのスクリプトを実行する必要がありますか? |
| magic output = script.out | マジック スクリプトの出力をどこに保存する必要がありますか? |

Sambaに接続する

```
$ smbclient -N -L //10.129.14.128        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers        home            Disk      INFREIGHT Samba
        dev             Disk      DEVenv
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)SMB1 disabled -- no workgroup available
```

```
$ smbclient //10.129.14.128/notesEnter WORKGROUP\<username>'s password:
Anonymous login successful
Try "help" to get a list of possible commands.

smb: \> help

?              allinfo        altname        archive        backup
blocksize      cancel         case_sensitive cd             chmod
chown          close          del            deltree        dir
du             echo           exit           get            getfacl
geteas         hardlink       help           history        iosize
lcd            link           lock           lowercase      ls
l              mask           md             mget           mkdir
more           mput           newer          notify         open
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir
posix_unlink   posix_whoami   print          prompt         put
pwd            q              queue          quit           readlink
rd             recurse        reget          rename         reput
rm             rmdir          showacls       setea          setmode
scopy          stat           symlink        tar            tarmode
timeout        translate      unlock         volume         vuid
wdel           logon          listconnect    showconnect    tcon
tdis           tid            utimes         logoff         ..
!

smb: \> ls

  .                                   D        0  Wed Sep 22 18:17:51 2021
  ..                                  D        0  Wed Sep 22 12:03:59 2021
  prep-prod.txt                       N       71  Sun Sep 19 15:45:21 2021

                30313412 blocks of size 1024. 16480084 blocks available
```

```
smb: \> get prep-prod.txt

getting file \prep-prod.txt of size 71 as prep-prod.txt (8,7 KiloBytes/sec)
(average 8,7 KiloBytes/sec)

smb: \> !ls

prep-prod.txt

smb: \> !cat prep-prod.txt

[] check your code with the templates
[] run code-assessment.py
[] …
```