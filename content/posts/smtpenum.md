---
title: "SMTP enumeration"
date: "2023-01-08"
draft: "false"
---

# SMTP

SMTP

送信と通信は、SMTP サーバーにユーザーの要求を実行させる特別なコマンドによっても行われます。

| 指示 | 説明 |
| --- | --- |
| AUTH PLAIN | AUTH は、クライアントの認証に使用されるサービス拡張です。 |
| HELO | クライアントはそのコンピューター名でログインし、セッションを開始します。 |
| MAIL FROM | クライアントは電子メールの送信者に名前を付けます。 |
| RCPT TO | クライアントは、電子メールの受信者に名前を付けます。 |
| DATA | クライアントが電子メールの送信を開始します。 |
| RSET | クライアントは開始された送信を中止しますが、クライアントとサーバー間の接続は維持します。 |
| VRFY | クライアントは、メールボックスがメッセージ転送に使用できるかどうかを確認します。 |
| EXPN | クライアントは、このコマンドでメールボックスがメッセージングに使用できるかどうかも確認します。 |
| NOOP | クライアントは、タイムアウトによる切断を防ぐために、サーバーに応答を要求します。 |
| QUIT | クライアントはセッションを終了します。 |

```jsx
$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server

HELO mail1.inlanefreight.htb

250 mail1.inlanefreight.htb

EHLO mail1

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

```jsx
$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server

EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING

MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok

RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok

DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work.
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB

QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

nmap

```jsx
$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

smtp-user-enum

```jsx
$ smtp-user-enum -w 20 -M VRFY -U /usr/share/wordlists/metasploit/common_roots.txt -t 10.129.234.8
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/metasploit/common_roots.txt
Target count ............. 1
Username count ........... 4725
Target TCP port .......... 25
Query timeout ............ 20 secs
Target domain ............

######## Scan started at Sat Dec 24 23:33:44 2022 #########
```

```jsx
msf6 > use auxiliary/scanner/smtp/smtp_enum
msf6 auxiliary(scanner/smtp/smtp_enum) > show options

Module options (auxiliary/scanner/smtp/smtp_enum):

   Name       Current Setting                                                Required  Description
   ----       ---------------                                                --------  -----------
   RHOSTS                                                                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      25                                                             yes       The target port (TCP)
   THREADS    1                                                              yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                                                           yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  /usr/share/metasploit-framework/data/wordlists/unix_users.txt  yes       The file that contains a list of probable users accounts.

View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/smtp/smtp_enum) > set ROSTS 10.129.190.229
[-] Unknown datastore option: ROSTS. Did you mean RHOST?
msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 10.129.190.229
RHOSTS => 10.129.190.229
msf6 auxiliary(scanner/smtp/smtp_enum) > run
```

```jsx
$ smtp-user-enum -w 20 -M VRFY -U ./tmp/footprinting-wordlist.txt -t mail1.inlanefreight.htb
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... ./tmp/footprinting-wordlist.txt
Target count ............. 1
Username count ........... 101
Target TCP port .......... 25
Query timeout ............ 20 secs
Target domain ............

######## Scan started at Sun Dec 25 01:29:47 2022 #########
mail1.inlanefreight.htb: robin exists
######## Scan completed at Sun Dec 25 01:33:13 2022 #########
1 results.

101 queries in 206 seconds (0.5 queries / sec)
```