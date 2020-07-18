---
layout: post
title: Hackthebox - Sauna
excerpt: "Sauna is an easy rated Windows machine and its' IP is 10.10.10.175. It retired today and here is my writeup about it."
categories: [writeups]
comments: true
tags: [hackthebox,writeup,username enumration,domain controller, active directory, impacket, pass the hash, python]
---

Sauna retired today and here is my write-up about it.
It is an `Easy` rated `Windows` machine and its' IP is `10.10.10.175`. First I found a web app running, and from there I gathered some usernames, which I used to perform `ASREPRoasting` without credentials on the user list. After I dumped `FSmith`s hash, I was able to crack it using `john` and then continued to gain initial access using `evil-winrm` with found credentials. For the privilege escalation part, using `WinPEAS` I was able to find a password in registry for user `svc_loanmgr` and using that password I dumped `Administrator`s NTLMv1 hash with `secretsdump.py` from impacket and then perform pass-the-hash using `psexec.py` to gain `Administrator` access.

![Sauna](/img/sauna-1.png)

#### Enumeration

First I start with a nmap scan
{% highlight bash %}
alb0z@parrot:~ # nmap -sC -sV -Pn -oA nmap/initial 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-17 13:27 CEST
Nmap scan report for 10.10.10.175
Host is up (0.17s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-17 18:30:16Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=7/17%Time=5F118B5C%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

{% endhighlight %}

The very first thing that I noticed after the scan, is that the machine seems to be a `DC (Domain Controller)` and the domain name is `EGOTISTICAL-BANK.LOCAL`, but we also see a web application running on port `80` which I will be using as my enumeration starting point.

At first sight there is nothing interesting as the website seems to be only an HTML template.

![Sauna](/img/sauna-2.png)

However, if visit `About Us` page which is `about.html` there are the names of team members, and we can use them to create a small user list.

![Sauna](/img/sauna-3.png)

#### Initial access

I am going to create the usernames in a format like below

![Sauna](/img/sauna-4.png)

Save the names in a file named `names.txt` and I wrote a simple python script to do the formating for us

{% highlight text %}
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
{% endhighlight %}


The python script:

{% highlight python %}
#!/usr/bin/env python3

file_name = "names.txt"

with open(file_name, "r") as f:
    lines = f.readlines()
    for line in lines:
        line = line.strip("\n") # remove the unneccesary new lines (\n)
        
        name = line.split(" ") # split the names by space
        # print the usernames in 3 different formats
        print(name[0] + name[1])
        print(name[0][:1] + name[1])
        print(name[0] + name[1][:1])
{% endhighlight %}

Run the script and redirect to output to a file, which we are going to use below

![Sauna](/img/sauna-5.png)

I tried some light bruteforcing on different services, but it didn't bring me anything. 

So now I am going to try to perform an attack called `ASREPRoasting`. You can read more about it <a href="https://blog.stealthbits.com/cracking-active-directory-passwords-with-as-rep-roasting/">here</a>

In short `ASREPRoasting` is an attack against `Kerberos` which will try to dump hashes from accounts that don't require `preauthentication`

I'm going to use `impacket`s module called `GetNPUsers.py`

![Sauna](/img/sauna-6.png)

Now `GetNPUsers.py` tries to get a hash and if it gets any, it saves the output into a desired file or it prints it in the screen. I gave the `-outputfile krb.hash` option so it's gonna save the hash into a file called `krb.hash`. In this case we get the hash for user `FSmith` and now we're going to try to crack it using `hashcat`.

![Sauna](/img/sauna-7.png)

Now we can see that the cracked password from the hash is `Thestrokes23` and as in a full nmap scan port `5985` was open, we can try to login using `evil-winrm` to gain initial access.

![Sauna](/img/sauna-8.png)

As we are logged in as FSmith and we have the user flag, we have now to find a way to privilege escalate to `Administrator` or `SYSTEM`.

#### Privilege Escalation

Next I'm going to use winPEAS which you can get <a href="https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASbat/winPEAS.bat">here</a>. And I'm setting up a webserver using pythons' http.server module to serve winPEAS so we can download it from the target. 
`sudo python3 -m http.server 80`

And I'm downloading the file using PowerShell
![Sauna](/img/sauna-9.png)

Running winPEAS and scrolling down slowly why analyzing the output, I came across some credentials in `HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon`

![Sauna](/img/sauna-10.png)

You can get the password directly using `reg query` too.

{% highlight bat %}
'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon"' | cmd
{% endhighlight %}

I tried the password against the `Administrator`s but it didn't work, however we can try to dump hashes using `secretsdump.py`. And as the DefaultUsername in `HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon` was `svc_loanmanager` I'm going to try to dump hashes from `svc_loanmgr` whose username can be found from the batch command `net user`.

![Sauna](/img/sauna-11.png)

As we have now dumped the NTLMv1 hash of `Administrator`, we can use `psexec.py` to pass the hash and login as `Administrator`

![Sauna](/img/sauna-12.png)