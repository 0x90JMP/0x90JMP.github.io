
# Basic Privilege Escalation And Enumeration

This is just a few basic searches we can do when we first gain a foothold on the target system. We will first look for some quick wins and then move onto searching for interesting files in common directories, along with searches for passwords and credentials.

We can then look for some missconfigurations, we can look for cron jobs and automated tasks that might bve runnig on the system. From there we will search for missconfigurations on files, binaries and directories. While searchiong for misconfigurations on binaries, we can search the binary version on things that stand out to us. 

lastly, we will take a look at kernel exploits for the kernel and Operation system version. Are there any updates that the system needs, are there any tools to compile possible Kernel exploits.

## **Searching For Fast Privesc**

When we gain access to the target system, we can upgrade or terminal if needed.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'

Ctrl + Z        <--- To background the process
stty raw -echo ; fg ; reset

export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 211; reset
```

In the shell we can start looking for some fast ways to escalate privileges. We start by running a few commands. We'll search for the current users groups, sudo privileges and take a look at to see if we can write to any interesting files.  

* User groups: is there anything interesting there? e.g. sudo, wheel, docker, adm, ldx
```
id 
```

* Lets then look to see if the current user can run any commands with elevated privileges.
```
sudo -l
```
