# Machine Name
```
Difficulty: Easy
Operating System: Linux
Hints: True
```
## Initial Enumeration
Running nmap scan (TCP) on the target shows the following results:
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)
80/tcp   open  http    nginx 1.19.0
|_http-server-header: nginx/1.19.0
| http-robots.txt: 1 disallowed entry 
|_/weather
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
|_http-title: 401 Unauthorized
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
|_http-server-header: Medusa/1.12
|_http-title: Error response
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd
```
As we can see this host is runnning NetBSD. As we can see on both port 80 and 9001 the service is requesting authentication, hence, we can see the response header ```401 Unauthorized``` .  
As we can see there's also a ```robots.txt``` file with a disallowed entry `/weather`
so let's dig into this.  
As we open the `/weather` page we get a 404 not found.  
Before moving our enumeration somewhere else, let's dig deeper into this directory.  
If we run directory enumeration against weather, we can see the following:  
`/forecast             (Status: 200) [Size: 90]`

## Foothold (optional)

## User
### Method 1 - Technique 1
### Method 2 - Technique 2

## Root
Once we log in, following our standard approach, we can run linPEAS looking for possible privilege escalation vectors.    
After we run linPEAS, we can notice
