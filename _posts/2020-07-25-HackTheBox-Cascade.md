---
layout: post
title: Hackthebox - Cascade
excerpt: "Cascade is a medium rated Windows machine and its' IP is 10.10.10.182. It retired today and here is my writeup about it."
categories: [writeups]
comments: true
tags: [hackthebox,writeup,ldap,brute force,username enumeration,smb enumeration,ldap enumeration,sqlite3]
---

Cascade retired today and here is my write-up about it. It is a `medium` rated Windows Machine and its' IP is `10.10.10.182`. First I start by enumerating `LDAP` and I come across a `base64` encoded password for the user `r.thompson`.  Then when enumerating `smb` I found another encrypted password in a file called `VNC Install.reg`, from there I found that `VNC` encrypts passwords with a fixed key, so it was possible for me to decrypt it. After that I passed the password to some services with some enumerated usernames from `ldap`, and `s.smith` resulted to have that password. Now in SMB I found an `sqlite3` database which had a password for user `ArkSvc`. I use `evil-winrm` to login as `ArkSvc` and the user is a member of `AD Recycle Bin`, so I'm able to recover deleted items, and this way I found a `base64` encoded password which was valid for `Administrator`.


![Cascade](/img/cascade-1.png)

#### Enumeration

First I start with a nmap scan

{% highlight bash %}
alb0z@parrot:~/Cascade # nmap -sC -sV -Pn -oA nmap/initial 10.10.10.182
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-25 13:02 CEST
Nmap scan report for 10.10.10.182
Host is up (0.061s latency).
Not shown: 986 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-25 11:06:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  unknown
49165/tcp open  unknown
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
{% endhighlight %}

First thing I notice, is that the machine is a `Domain Controller` running on a `Windows Server 2008 R2 SP1` and its' domain is `cascade.local` .

Now as `ldap` is the lowest port I can enumerate right now, I am going to be starting with it.
![Cascade](/img/cascade-2.png)

Let's fetch data from `DC=cascade,DC=local`, and save the data to a file to further analyze it.

![Cascade](/img/cascade-3.png)

Greping for interesting strings such as `pass` `password` `pwd` brings us an interesting query named `cascadeLegacyPwd`, that seems to be base64 decoded. So I decode it and it looks like it is a password. 

![Cascade](/img/cascade-4.png)

Now if we print 15 lines before the match, we see that the password belongs to user `r.thompson` and if I try it in SMB it works.

![Cascade](/img/cascade-5.png)

As we see that query `sAMAccountName` contains usernames, let's grep all the usernames and save it to a file for later use.

What the command does is simply grep for lines containing `sAMAccountName`, separate the field using `:` as a delimiter, remove the first space from each line, and then remove all lines which contain spaces in names so we only have valid usernames.

![Cascade](/img/cascade-6.png)

Now continuing where we left off. I connect to smb `Data` share, which we discovered above. And download everything we have access there.

![Cascade](/img/cascade-7.png)

`VNC Install.reg` seems interesting. So we when take a look, we discover an interesting query, which looks like hex encoded, but it is also encrypted.

![Cascade](/img/cascade-8.png)

Now according to this page <a href="https://github.com/frizb/PasswordDecrypts">https://github.com/frizb/PasswordDecrypts</a> VNC uses a hardcoded key to encrypt the passwords, and it also tells us how to decrypt it using metasploit. So now let's follow his steps and decrypt the password.

![Cascade](/img/cascade-9.png)

So the decrypted password is `sT333ve2`, and now let's use `crackmapexec` to see to who does the password belong. Also I'm going to use the usernames we saved earlier.

![Cascade](/img/cascade-10.png)

Password `sT333ve2` seems to be valid for user `s.smith`

After some enumeration on SMB, I came across this .db file in `Audit$` share which seems to be an `sqlite3` database, I download it to further see what's in there.

![Cascade](/img/cascade-11.png)

Now after I confirm that it is a sqlite3 file, I continue to fetch data from it and discover a `base64` "encoded" password for user `ArkSvc`
The passwords seems base64 encoded, however it is encrypted.

![Cascade](/img/cascade-12.png)

A quick search on google for `"BQO5l5Kj9MdErXx6Q6AGOw=="` brings us this URL <a href="https://dotnetfiddle.net/2RDoWz">https://dotnetfiddle.net/2RDoWz</a> . I'm not sure if this is the intended way, or some user left the code in there with the decryption keys.

![Cascade](/img/cascade-13.png)

The password seems to be `w3lc0meFr31nd`, and now I'll try it to login as ArkSvc using `evil-winrm`.

![Cascade](/img/cascade-14.png)

Now if we type `net user arksvc` we see that `arksvc` is a member of `AD Recycle Bin` group.

![Cascade](/img/cascade-15.png)

According to this page <a href="https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/">https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/</a> we should be able to recover deleted items from the machine.

![Cascade](/img/cascade-16.png)

Taking a look at the docs of `Get-ADObject` and reading a bit <a href="https://docs.microsoft.com/en-us/powershell/module/addsadministration/Get-ADObject?view=win10-ps">https://docs.microsoft.com/en-us/powershell/module/addsadministration/Get-ADObject?view=win10-ps</a> . I was able to find how to fetch the deleted objects

![Cascade](/img/cascade-17.png)

If we base64 decode the string, we get the password for `Administrator` and use `psexec.py` from impacket to gain `Administrator` access

![Cascade](/img/cascade-18.png)