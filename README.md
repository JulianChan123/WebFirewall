# WebFirewall
A python application to detect multiple http requests from the same IP in a short period of time. This app detect a suspicious ip and block it for prevent DoS &amp; Brute Forcing attacks.

To run the script you need to have installed:
- tcpdump
- ufw

First you have to enable ufw:
>sudo ufw enable

Run the script:
>python3 WAF.py -p {port} -t {threshold} -i {interval}

For more information you can use:
>python WAF.py --help

### PoC:

DoS attack example:

![alt text](https://i.ibb.co/RQPtTG4/Do-SExample.jpg)

Script detects and block:

![alt text](https://i.ibb.co/BCK8q5t/Script-Running.jpg)